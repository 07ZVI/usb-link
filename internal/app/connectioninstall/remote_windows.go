//go:build windows && amd64

package connectioninstall

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/app/remoteupdate"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/security/usbgateway"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var errRemoteMaintenanceRemoved = fmt.Errorf("REMOTE_MAINTENANCE_REMOVED")

const remoteACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
const remoteRule = "Suhang-Remote-Update-7c494949-v1"

type remoteConfig struct {
	Enabled     bool   `json:"enabled"`
	AutoUpgrade bool   `json:"auto_upgrade"`
	Token       string `json:"token"`
	Cert, Key   []byte
}
type UpdateJob struct {
	CandidateFailure    remoteupdate.CandidateFailure `json:"candidate_failure,omitempty"`
	ID                  string                        `json:"id"`
	Old, Target         string
	Manifest            remoteupdate.Manifest
	Status              string `json:"status"`
	Detail              string `json:"detail,omitempty"`
	Guarded             bool   `json:"guarded,omitempty"`
	OwnerPID            uint32 `json:"owner_pid,omitempty"`
	OwnerExecutable     string `json:"owner_executable,omitempty"`
	OwnerCreation       uint64 `json:"owner_creation_filetime,omitempty"`
	CandidatePID        uint32 `json:"candidate_pid,omitempty"`
	CandidateCreation   uint64 `json:"candidate_creation_filetime,omitempty"`
	CandidateExecutable string `json:"candidate_executable,omitempty"`
	UpdatedUTC          string `json:"updated_utc,omitempty"`
}
type RemoteManager struct {
	candidateStatusMu         sync.Mutex
	startupFailureDetails     func() remoteupdate.CandidateStartupObservation
	richStartupFailureDetails func() *remoteupdate.CandidateRichObservation
	upgradeGuard              upgradeGuardState
	closing                   atomic.Bool
	measurements              measurementState
	usbGUID                   func() string
	approve                   func(string) bool
	notify                    func(string, string) error
	consentRevision           uint64
	done                      chan struct{}
	api                       *remoteupdate.Server
	lastError                 string
	mu                        sync.Mutex
	root, version, installed  string
	runtimeStatus             func() (string, string)
	runtimeDetails            func() any
	config                    remoteConfig
	server                    *http.Server
	nativeGeneration          func() bool
	stop                      context.CancelFunc
	requested                 atomic.Bool
	recoveryOnly              bool
	recoveryAPI               *remoteupdate.Server
	rawUSB                    atomic.Bool
	recoveryTest              func() error
	ipadDiagnostic            func(string) (any, error)
	ipadDiagnosticBusy        func() bool
}

func remoteRoot() (string, error) {
	root, e := maintenanceBase()
	if e != nil {
		return "", e
	}
	dir := filepath.Join(root, "Remote Maintenance")
	sd, e := windows.SecurityDescriptorFromString(remoteACL)
	if e != nil {
		return "", e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	e = windows.CreateDirectory(windows.StringToUTF16Ptr(dir), &sa)
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return "", e
	}
	if noReparse(dir) != nil {
		return "", fmt.Errorf("redirected maintenance directory")
	}
	actual, e := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil || !sameACL(actual, sd) {
		return "", fmt.Errorf("maintenance ACL changed")
	}
	return dir, nil
}
func writeRemote(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), "state-")
	if e != nil {
		return e
	}
	p := f.Name()
	defer os.Remove(p)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(p), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func readRemote(path string, v any) error {
	if e := noReparse(path); e != nil {
		return e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(b) > 32768 {
		return fmt.Errorf("state too large")
	}
	return json.Unmarshal(b, v)
}
func NewRemoteManager(version, installed string, stop context.CancelFunc, usbGUID func() string, approve func(string) bool) (*RemoteManager, error) {
	return newRemoteManager(version, installed, stop, usbGUID, approve, false)
}

func NewRecoveryRemoteManager(version, installed string, stop context.CancelFunc, usbAttached func() string, approve func(string) bool) (*RemoteManager, error) {
	if e := Verify(installed); e != nil {
		return nil, e
	}
	return newRemoteManager(version, installed, stop, usbAttached, approve, true)
}

func newRemoteManager(version, installed string, stop context.CancelFunc, usbGUID func() string, approve func(string) bool, recovery bool) (*RemoteManager, error) {
	root, e := remoteRoot()
	if e != nil {
		return nil, e
	}
	m := &RemoteManager{root: root, version: version, installed: installed, stop: stop, usbGUID: usbGUID, approve: approve, done: make(chan struct{}), recoveryOnly: recovery}
	m.upgradeGuard.enabled.Store(upgradeGuardInherited())
	e = readRemote(filepath.Join(root, "config.json"), &m.config)
	if e != nil && !os.IsNotExist(e) {
		return nil, fmt.Errorf("read maintenance configuration: %w", e)
	}
	// Retain the protected local transaction journal for rollback compatibility,
	// but never honor old network or automatic-install consent.
	m.config = remoteConfig{}
	pendingID := startupAckJobID()
	deferConsentClear := false
	if pendingID != "" && ValidateRemoteLaunch(pendingID, version) == nil {
		// The old worker still owns rollback. Do not erase its original consent
		// until this exact candidate is accepted; public APIs remain unavailable.
		deferConsentClear = true
	} else {
		if e = writeRemote(filepath.Join(root, "config.json"), m.config); e != nil {
			return nil, e
		}
	}
	activeUpgradeManager.Store(m)
	if upgradeGuardInherited() {
		if e = m.guardSet(900); e != nil {
			return nil, e
		}
	}
	if !recovery {
		if e = remoteFirewall(false, ""); e != nil {
			return nil, e
		}
	}
	var previous UpdateJob
	if readRemote(filepath.Join(root, "job.json"), &previous) == nil && (previous.Status == "awaiting_local_approval" || previous.Status == "awaiting_auto_install") {
		if previous.Guarded {
			if err := interruptDeadUpgradeJob(root, previous, "Exact previous owner exited before authorization completed; recovery records retained"); err != nil {
				m.lastError = "Previous guarded authorization retained: " + err.Error()
			}
		} else {
			previous.Status = "declined"
			previous.Detail = "Previous process ended before update authorization completed"
			_ = persistUpdateJob(root, previous)
		}
	}
	if deferConsentClear {
		go m.retireLegacyConsentAfterCommit(pendingID)
	}
	return m, nil
}

func (m *RemoteManager) retireLegacyConsentAfterCommit(id string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.candidateStatusMu.Lock()
			if m.closing.Load() {
				m.candidateStatusMu.Unlock()
				return
			}
			var job UpdateJob
			accepted := readRemote(filepath.Join(m.root, "job.json"), &job) == nil && job.ID == id && job.Status == "complete" && job.Manifest.Version == m.version
			if accepted {
				hash, err := fileHash(m.installed)
				accepted = err == nil && hash == job.Manifest.SHA256 && Verify(m.installed) == nil
			}
			if accepted {
				err := writeRemote(filepath.Join(m.root, "config.json"), remoteConfig{})
				m.candidateStatusMu.Unlock()
				if err == nil {
					return
				}
				continue
			}
			m.candidateStatusMu.Unlock()
		}
	}
}

// RecoveryAPI cannot expose the former raw-USB remote maintenance service.
func (m *RemoteManager) RecoveryAPI() (http.Handler, *tls.Config, error) {
	return nil, nil, errRemoteMaintenanceRemoved
}

func (m *RemoteManager) RecoveryInvitation() ([]byte, error) { return nil, errRemoteMaintenanceRemoved }

func remoteFirewall(enabled bool, guid string) error {
	if enabled {
		return errRemoteMaintenanceRemoved
	}
	if netconfig.NativeNetworkEnabled() {
		return remoteFirewallNative(enabled, guid)
	}
	script := `$r=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -ceq '` + remoteRule + `'});if($r.Count -gt 0){if(@($r|Where-Object {$_.Group -cne 'Suhang-Remote-Maintenance-v1'}).Count){throw 'Rule ownership changed'};$r|Remove-NetFirewallRule -ErrorAction Stop};`

	if !enabled {
		cleanup, e := measurementFirewallScript(false, "", "", "")
		if e != nil {
			return e
		}
		script += cleanup
		icmp, e := measurementICMPFirewallScript(false, "", "")
		if e != nil {
			return e
		}
		script += icmp
	}
	return netconfig.Run(script, log.New(io.Discard, "", 0))
}
func (m *RemoteManager) open() error { return errRemoteMaintenanceRemoved }

func (m *RemoteManager) Enable(enabled bool) error {
	if enabled {
		return errRemoteMaintenanceRemoved
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = remoteConfig{}
	m.consentRevision++
	return writeRemote(filepath.Join(m.root, "config.json"), m.config)
}

func (m *RemoteManager) SetAutoUpgrade(enabled bool) error {
	if enabled {
		return errRemoteMaintenanceRemoved
	}
	return m.Enable(false)
}

func (m *RemoteManager) AutoUpgrade() bool { return false }

func (m *RemoteManager) SetUpdateNotifier(f func(string, string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notify = f
}
func (m *RemoteManager) notifyUpdate(version, phase string) error {
	m.mu.Lock()
	f := m.notify
	m.mu.Unlock()
	if f == nil {
		return fmt.Errorf("local update notification unavailable")
	}
	return f(version, phase)
}
func (m *RemoteManager) Close() {
	if !m.closing.CompareAndSwap(false, true) {
		return
	}
	activeUpgradeManager.CompareAndSwap(m, nil)
	m.mu.Lock()
	m.upgradeGuard.generation++
	m.upgradeGuard.enabled.Store(false)
	if m.upgradeGuard.timer != nil {
		m.upgradeGuard.timer.Stop()
	}
	committed := m.upgradeGuard.committed
	id := m.upgradeGuard.jobID
	m.mu.Unlock()
	if !committed {
		if id != "" {
			// A failed write retains the original record and admission until this
			// actual process exits. Startup may then prove the exact owner dead.
			_ = m.cancelGuardJob(id, "Maintenance process closed before handoff")
		} else {
			m.guardRelease()
		}
	}
	_, _ = setDesktopRuntimeExperiment("CDEFAULT", 0)
	m.stopMeasurements()
	close(m.done)
	// Join any candidate-only fixed receipt write before tearing down the owner.
	m.candidateStatusMu.Lock()
	m.candidateStatusMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server != nil {
		m.server.Close()
		m.server = nil
	}
	if !m.recoveryOnly {
		remoteFirewall(false, "")
	}
}
func (m *RemoteManager) Requested() bool { return m != nil && m.requested.Load() }
func (m *RemoteManager) Info() (string, string) {
	return "Remote maintenance is not available in the public build", ""
}

func (m *RemoteManager) status() any {
	var j UpdateJob
	readErr := readRemote(filepath.Join(m.root, "job.json"), &j)
	if retry := m.upgradeGuard.retrySnapshot.Load(); retry != nil {
		result := map[string]string{"id": retry.id, "version": retry.version, "status": "persistence_recovery_required", "detail": retry.detail, "persistence_retry": "true", "retry_job_id": retry.id, "deployment_state": "pending_persistence", "current_version": m.version}
		if readErr == nil {
			result["persisted_status"] = j.Status
			result["persisted_job_id"] = j.ID
		}
		if remoteUSBHealthy() && !m.recoveryOnly {
			result["usb_state"] = "verified"
		} else {
			result["usb_state"] = "unverified"
		}
		return result
	}
	if unknown := m.upgradeGuard.launchUnknown.Load(); unknown != nil {
		result := map[string]string{"id": unknown.id, "version": unknown.version, "status": "manual_recovery_required", "detail": unknown.detail, "deployment_state": "worker_creation_unconfirmed", "current_version": m.version, "usb_state": "unverified"}
		if readErr == nil {
			result["persisted_status"], result["persisted_job_id"] = j.Status, j.ID
		}
		if remoteUSBHealthy() && !m.recoveryOnly {
			result["usb_state"] = "verified"
		}
		return result
	}
	if readErr != nil {
		return map[string]string{"status": "idle"}
	}
	result := map[string]string{"id": j.ID, "version": j.Manifest.Version, "status": j.Status, "detail": j.Detail}
	for k, v := range candidateFailureStatus(j) {
		result[k] = v
	}
	if j.Guarded || m.guardEnabled() {
		status, deployment, usb := remoteupdate.ReportProgress(j.Status, j.Manifest.Version, m.version, remoteUSBHealthy(), m.recoveryOnly)
		result["status"] = status
		result["deployment_state"] = deployment
		result["usb_state"] = usb
		result["current_version"] = m.version
		result["persisted_status"] = j.Status
	}
	return result
}
func (m *RemoteManager) stage(manifest remoteupdate.Manifest, body io.Reader) (string, error) {
	return "", errRemoteMaintenanceRemoved
}

func (m *RemoteManager) apply(api *remoteupdate.Server, id string) error {
	return errRemoteMaintenanceRemoved
}

func (m *RemoteManager) Enabled() bool { return false }

func (m *RemoteManager) Snapshot() any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{"enabled": m.config.Enabled, "auto_upgrade": m.config.AutoUpgrade, "listening": m.server != nil, "listener_error": m.lastError, "update": m.status()}
}

// Uninstall revokes the persistent credentials even if update evidence is retained.
func RemoveRemoteAccess() error {
	root, e := remoteRoot()
	if e != nil {
		return e
	}
	if e = writeRemote(filepath.Join(root, "config.json"), remoteConfig{}); e != nil {
		return e
	}
	return remoteFirewall(false, "")
}

// Assigned once before a USB session can open the listener.
func (m *RemoteManager) SetRuntimeStatus(f func() (string, string)) {
	m.mu.Lock()
	m.runtimeStatus = f
	m.mu.Unlock()
	if f != nil {
		s, _ := f()
		m.guardStartupRecoveryAck(s)
	}
}
func (m *RemoteManager) SetRuntimeDetails(f func() any) { m.runtimeDetails = f }
func (m *RemoteManager) diagnostics() any {
	status, problem := "unavailable", ""
	if m.runtimeStatus != nil {
		status, problem = m.runtimeStatus()
	}
	result := map[string]any{"gateway": usbgateway.Evidence(), "process_id": os.Getpid(), "connection_status": status, "connection_error": problem, "developer": m.ListenerStatus()}
	result["installation_cleanup"] = InstallationCleanupStatus()
	result["candidate_startup_diagnostics"] = m.CandidateStartupRichDiagnostics()
	if m.runtimeDetails != nil {
		result["sessions"] = m.runtimeDetails()
	}
	return result
}

// ListenerStatus excludes update jobs, tokens and certificate/key material.
func (m *RemoteManager) ListenerStatus() any {
	m.mu.Lock()
	defer m.mu.Unlock()
	errText := m.lastError
	if len(errText) > 512 {
		errText = errText[:512]
	}
	return map[string]any{"version": m.version, "enabled": m.config.Enabled, "auto_upgrade": m.config.AutoUpgrade, "listening": m.server != nil || (m.rawUSB.Load() && m.config.Enabled), "recovery_transport": m.rawUSB.Load(), "listener_error": errText}
}

// SetRecoveryAttached is set only after normal USB device admission and NCM
// initialization, and cleared before closing that physical function.
func (m *RemoteManager) SetRecoveryAttached(v bool) { m.rawUSB.Store(v) }

// Caller holds mu. A raw session is separate from the normal network API so
// listener retries cannot silently rotate an in-progress recovery authorization.
func (m *RemoteManager) apiActive(api *remoteupdate.Server) bool {
	return (api == m.api && m.usbGUID() != "") || (api == m.recoveryAPI && m.rawUSB.Load())
}

func (m *RemoteManager) SetRecoveryTest(f func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoveryTest = f
}
func (m *RemoteManager) runRecoveryTest() error {
	m.mu.Lock()
	valid := m.config.Enabled && !m.requested.Load() && !m.rawUSB.Load() && m.usbGUID() != ""
	f := m.recoveryTest
	m.mu.Unlock()
	if !valid || f == nil {
		return fmt.Errorf("normal USB maintenance required")
	}
	var job UpdateJob
	if readRemote(filepath.Join(m.root, "job.json"), &job) == nil && (job.Status == "staged" || job.Status == "awaiting_auto_install" || job.Status == "awaiting_local_approval" || job.Status == "installing") {
		return fmt.Errorf("upgrade job pending")
	}
	return f()
}
