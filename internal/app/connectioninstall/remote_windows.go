//go:build windows && amd64

package connectioninstall

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/security/usbgateway"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

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
	if !recovery {
		go m.watch()
	}
	return m, nil
}

// RecoveryAPI uses the same TLS identity, bearer token, signed release checks,
// local approval and worker as normal maintenance, without an OS TCP listener.
func (m *RemoteManager) RecoveryAPI() (http.Handler, *tls.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.config.Enabled || !m.rawUSB.Load() {
		return nil, nil, fmt.Errorf("USB developer debugging is disabled")
	}
	pair, e := tls.X509KeyPair(m.config.Cert, m.config.Key)
	if e != nil || len(m.config.Token) != 64 {
		return nil, nil, fmt.Errorf("maintenance credentials invalid")
	}
	api := m.recoveryAPI
	if api == nil {
		api = &remoteupdate.Server{Version: m.version, Token: m.config.Token, Key: remoteupdate.PublisherKey(), Stage: m.stage, Status: m.status, Diagnostics: m.diagnostics, Performance: http.HandlerFunc(m.guardPerformance)}
		api.Apply = func(id string) error { return m.apply(api, id) }
		m.guardAPI(api)
		m.recoveryAPI = api
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		enabled := m.config.Enabled && m.recoveryAPI == api
		m.mu.Unlock()
		if !enabled || !m.rawUSB.Load() {
			http.Error(w, "USB authorization unavailable", 403)
			return
		}
		api.ServeHTTP(w, r)
	})
	return h, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, nil
}

func (m *RemoteManager) RecoveryInvitation() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.config.Enabled || !m.rawUSB.Load() {
		return nil, fmt.Errorf("USB debugging unavailable")
	}
	block, _ := pem.Decode(m.config.Cert)
	if block == nil || len(m.config.Token) != 64 {
		return nil, fmt.Errorf("maintenance credentials invalid")
	}
	pin := sha256.Sum256(block.Bytes)
	return json.Marshal(map[string]any{"urls": []string{"https://10.6.9.1:47775"}, "certificate_sha256": hex.EncodeToString(pin[:]), "token": m.config.Token, "transport": "usb-recovery"})
}
func newRemoteConfig() (remoteConfig, error) {
	var c remoteConfig
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return c, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return c, e
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "USB Link Remote Maintenance"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
	if e != nil {
		return c, e
	}
	priv, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return c, e
	}
	var token [32]byte
	if _, e = rand.Read(token[:]); e != nil {
		return c, e
	}
	c.Enabled = true
	c.Token = hex.EncodeToString(token[:])
	c.Cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	c.Key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})
	return c, nil
}
func remoteFirewall(enabled bool, guid string) error {
	if netconfig.NativeNetworkEnabled() {
		return remoteFirewallNative(enabled, guid)
	}
	script := `$r=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -ceq '` + remoteRule + `'});if($r.Count -gt 0){if(@($r|Where-Object {$_.Group -cne 'Suhang-Remote-Maintenance-v1'}).Count){throw 'Rule ownership changed'};$r|Remove-NetFirewallRule -ErrorAction Stop};`
	if enabled {
		if _, e := windows.GUIDFromString(guid); e != nil {
			return e
		}
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		script += `$a=@(Get-NetAdapter -IncludeHidden|Where-Object {[guid]$_.InterfaceGuid -eq [guid]'` + guid + `' -and $_.Name -ceq 'USB Link'});if($a.Count -ne 1){throw 'USB adapter identity changed'};New-NetFirewallRule -Name '` + remoteRule + `' -DisplayName 'USB Link signed upgrades' -Group 'Suhang-Remote-Maintenance-v1' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47775 -RemoteAddress '10.6.9.2' -LocalAddress '10.6.9.1' -InterfaceAlias $a[0].Name -Profile Any -Program '` + strings.ReplaceAll(exe, "'", "''") + `' -ErrorAction Stop|Out-Null;`
	}
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
func (m *RemoteManager) open() error {
	guid := m.usbGUID()
	if guid == "" {
		return nil
	}
	var nativeGeneration func() bool
	if netconfig.NativeNetworkEnabled() {
		var e error
		nativeGeneration, e = nativeMaintenanceGenerationGuard(guid)
		if e != nil {
			return e
		}
	}
	pair, e := tls.X509KeyPair(m.config.Cert, m.config.Key)
	if e != nil || len(m.config.Token) != 64 {
		return fmt.Errorf("maintenance credentials invalid")
	}
	l, e := net.Listen("tcp4", "10.6.9.1:47775")
	if e != nil {
		return e
	}
	if e = remoteFirewall(true, guid); e != nil {
		l.Close()
		return e
	}
	if m.usbGUID() != guid || nativeGeneration != nil && !nativeGeneration() {
		l.Close()
		return fmt.Errorf("MAINTENANCE_USB_GENERATION_CHANGED")
	}
	api := &remoteupdate.Server{Version: m.version, Token: m.config.Token, Key: remoteupdate.PublisherKey(), Stage: m.stage, Status: m.status, Diagnostics: m.diagnostics, RecoveryTest: m.runRecoveryTest, Performance: http.HandlerFunc(m.performance)}
	api.Apply = func(id string) error { return m.apply(api, id) }
	m.guardAPI(api)
	m.api = api
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, _, _ := net.SplitHostPort(r.RemoteAddr)
		if peer != "10.6.9.2" || m.usbGUID() != guid || nativeGeneration != nil && !nativeGeneration() {
			http.Error(w, "USB peer required", 403)
			return
		}
		api.ServeHTTP(w, r)
	})
	m.server = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 180 * time.Second, WriteTimeout: 180 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}}
	m.nativeGeneration = nativeGeneration
	server := m.server
	go server.Serve(tls.NewListener(l, server.TLSConfig))
	return nil
}
func (m *RemoteManager) Enable(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.requested.Load() {
		return fmt.Errorf("update handoff in progress")
	}
	m.consentRevision++
	m.recoveryAPI = nil
	if m.server != nil {
		m.server.Close()
		m.server = nil
	}
	m.config.Enabled = false
	if e := writeRemote(filepath.Join(m.root, "config.json"), m.config); e != nil {
		return e
	}
	if !m.recoveryOnly {
		if e := remoteFirewall(false, ""); e != nil {
			return e
		}
	}
	if enabled {
		c, e := newRemoteConfig()
		if e != nil {
			return e
		}
		m.config = c
	} else {
		m.config = remoteConfig{}
	}
	if e := writeRemote(filepath.Join(m.root, "config.json"), m.config); e != nil {
		return e
	}
	if enabled {
		e := m.open()
		m.lastError = ""
		if e != nil {
			m.lastError = e.Error()
		}
		return e
	}
	return nil
}

// Only the local native settings IPC calls this method. The remote API cannot
// grant installation consent. Persist before publishing; failed writes retain
// the previous choice. Disabling debug clears this authorization too.
func (m *RemoteManager) SetAutoUpgrade(enabled bool) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("local administrator required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.requested.Load() {
		return fmt.Errorf("update handoff in progress")
	}
	if enabled && !m.config.Enabled {
		return fmt.Errorf("enable USB developer debugging first")
	}
	c := m.config
	c.AutoUpgrade = enabled
	if err := writeRemote(filepath.Join(m.root, "config.json"), c); err != nil {
		return err
	}
	m.config = c
	m.consentRevision++
	return nil
}
func (m *RemoteManager) AutoUpgrade() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config.Enabled && m.config.AutoUpgrade
}
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
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.status()
	b, _ := json.Marshal(state)
	if !m.config.Enabled {
		return "開發者調試未開啟。" + string(b), ""
	}
	if m.rawUSB.Load() {
		return "USB 恢復維護已連接 · " + m.version + "\n" + string(b), ""
	}
	if m.server == nil {
		return "開發者調試已開啟，等候 Mac USB 連線。" + m.lastError, ""
	}
	block, _ := pem.Decode(m.config.Cert)
	if block == nil {
		return "憑證無效", ""
	}
	pin := sha256.Sum256(block.Bytes)
	urls := []string{"https://10.6.9.1:47775"}
	inv, _ := json.Marshal(map[string]any{"urls": urls, "certificate_sha256": hex.EncodeToString(pin[:]), "token": m.config.Token})
	return "USB 開發者調試已開啟 · " + m.version + "\n" + string(b), string(inv)
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
	if m.closing.Load() {
		return "", fmt.Errorf("maintenance process exiting")
	}
	guarded := m.guardEnabled()
	m.mu.Lock()
	owned := m.upgradeGuard.release != nil
	m.mu.Unlock()
	if owned {
		return "", fmt.Errorf("guarded maintenance owner still reserved; recover exact idle job first")
	}
	if m.measurementBusy() || !guarded && m.ipadDiagnosticActive() {
		return "", fmt.Errorf("resource capture active; finish before upgrade")
	}
	installationCleanupMu.Lock()
	defer installationCleanupMu.Unlock()
	if manifest.Verify(remoteupdate.PublisherKey(), m.version, time.Now()) != nil {
		return "", fmt.Errorf("signature rejected")
	}
	var reservationGeneration uint64
	if guarded {
		var err error
		reservationGeneration, err = m.guardReserve()
		if err != nil {
			return "", err
		}
	}
	reservedSuccess := false
	defer func() {
		if guarded && !reservedSuccess {
			m.guardReleaseGeneration(reservationGeneration)
		}
	}()
	var previous UpdateJob
	if readRemote(filepath.Join(m.root, "job.json"), &previous) == nil && remoteupdate.UpdateInFlight(previous.Status) && (guarded || previous.Guarded || previous.Status != "manual_recovery_required" && previous.Status != "rollback") {
		if !guarded {
			return "", fmt.Errorf("previous update pending")
		}
		childKnown, childAlive := true, false
		if previous.Guarded && (previous.Status == "starting" || previous.Status == "manual_recovery_required") {
			childKnown = false
			if previous.CandidatePID != 0 {
				candidate := previous
				candidate.OwnerPID = previous.CandidatePID
				candidate.OwnerCreation = previous.CandidateCreation
				candidate.OwnerExecutable = previous.CandidateExecutable
				var childErr error
				childKnown, childAlive, childErr = recordedOwner(candidate)
				if childErr != nil {
					return "", childErr
				}
			}
		}
		recorded, alive, err := recordedOwner(previous)
		if err != nil {
			return "", err
		}
		block, interrupted := remoteupdate.ClassifyJob(previous.Status, recorded, alive)
		if previous.Guarded {
			block, interrupted = remoteupdate.ClassifyRepair(previous.Status, recorded, alive, childKnown, childAlive)
		}
		if block {
			return "", fmt.Errorf("previous update owner still active or unverified")
		}
		if interrupted {
			if err = interruptDeadUpgradeJob(m.root, previous, "Recorded update owner exited; signed bytes and recovery receipts retained"); err != nil {
				return "", err
			}
		}
	}
	dir, e := os.MkdirTemp(m.root, "release-")
	if e != nil {
		return "", e
	}
	path := filepath.Join(dir, "release.exe")
	ok := false
	defer func() {
		if !ok {
			os.Remove(path)
			os.Remove(dir)
		}
	}()
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	e = remoteupdate.VerifyBinary(io.TeeReader(body, f), manifest)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return "", e
	}
	if ce != nil {
		return "", ce
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return "", e
	}
	id := hex.EncodeToString(nonce[:])
	j := UpdateJob{ID: id, Old: m.installed, Target: path, Manifest: manifest, Status: "staged", Guarded: guarded}
	if guarded {
		j.OwnerPID = uint32(os.Getpid())
		j.OwnerExecutable = m.installed
		j.OwnerCreation, e = processCreation(j.OwnerPID)
		if e != nil {
			return "", e
		}
	}
	if e = persistUpdateJob(m.root, j); e != nil {
		if guarded {
			var durable UpdateJob
			readErr := readRemote(filepath.Join(m.root, "job.json"), &durable)
			if readErr == nil && durable.ID == id && sameStorageRetryJob(durable, j) || readErr != nil && !os.IsNotExist(readErr) {
				m.mu.Lock()
				m.upgradeGuard.jobID = id
				owned := j
				m.upgradeGuard.ownedJob = &owned
				e = m.retainGuardStorageLocked(nil, j, []string{"staged"}, "failed", "Initial staging persistence unconfirmed; signed bytes retained", e)
				m.mu.Unlock()
				ok, reservedSuccess = true, true
				return id, e
			}
		}
		return "", e
	}
	if guarded {
		m.mu.Lock()
		m.upgradeGuard.jobID = id
		owned := j
		m.upgradeGuard.ownedJob = &owned
		m.mu.Unlock()
	}
	if e = m.notifyUpdate(manifest.Version, "received"); e != nil {
		j.Status, j.Detail = "failed", "Local receipt notification failed"
		if saveErr := persistUpdateJob(m.root, j); saveErr != nil && guarded {
			m.mu.Lock()
			e = m.retainGuardStorageLocked(nil, j, []string{"staged", "failed"}, "failed", j.Detail, saveErr)
			m.mu.Unlock()
			ok, reservedSuccess = true, true
			return id, e
		}
		return "", e
	}
	if guarded {
		m.mu.Lock()
		valid := m.guardEnabled() && m.config.Enabled && !m.closing.Load() && m.upgradeGuard.reservationGeneration == reservationGeneration
		if valid {
			m.upgradeGuard.jobID = id
		}
		m.mu.Unlock()
		if !valid {
			if cancelErr := m.cancelGuardJob(id, "Experiment expired while staging"); cancelErr != nil {
				ok, reservedSuccess = true, true
				return id, cancelErr
			}
			return "", fmt.Errorf("upgrade experiment expired")
		}
	}
	ok, reservedSuccess = true, true
	return id, nil
}
func (m *RemoteManager) apply(api *remoteupdate.Server, id string) (err error) {
	defer func() {
		if err != nil {
			m.mu.Lock()
			var owned UpdateJob
			if m.upgradeGuard.retry != nil && m.upgradeGuard.jobID == id && !m.upgradeGuard.launchAttempted {
				err = remoteupdate.RetainJobError(err)
			} else if m.upgradeGuard.ownedJob != nil && m.upgradeGuard.ownedJob.ID == id {
				// Storage may itself be unreadable. The live in-memory reservation
				// preserves the API slot; cancellation still verifies durable identity.
				owned = *m.upgradeGuard.ownedJob
				err = m.retainGuardStorageLocked(api, owned, []string{"staged", "awaiting_local_approval", "awaiting_auto_install"}, "cancelled", "Apply failed before worker launch; explicitly cancel retained job", err)
			} else if readRemote(filepath.Join(m.root, "job.json"), &owned) == nil && owned.ID == id && owned.Guarded {
				err = m.retainGuardStorageLocked(api, owned, []string{"staged", "awaiting_local_approval", "awaiting_auto_install"}, "cancelled", "Apply failed before worker launch; explicitly cancel retained job", err)
			}
			m.mu.Unlock()
		}
	}()
	if m.closing.Load() {
		return fmt.Errorf("maintenance process exiting")
	}
	m.mu.Lock()
	active := m.config.Enabled && m.apiActive(api)
	automatic, revision := m.config.AutoUpgrade, m.consentRevision
	m.mu.Unlock()
	if !active {
		return fmt.Errorf("debug authorization revoked")
	}
	j, e := validatedJob(id, m.version)
	if e != nil {
		return e
	}
	m.mu.Lock()
	usbAvailable := m.apiActive(api)
	guardAdmitted := m.guardEnabled() && m.upgradeGuard.jobID == id
	m.mu.Unlock()
	if j.Guarded && !guardAdmitted {
		return fmt.Errorf("upgrade experiment or reservation expired")
	}
	if j.Status != "staged" || !usbAvailable {
		return fmt.Errorf("not staged or USB unavailable")
	}
	j.Status = "awaiting_local_approval"
	if automatic {
		j.Status = "awaiting_auto_install"
	}
	if e = persistUpdateJob(m.root, j); e != nil {
		return e
	}
	go func() {
		yes := automatic || (m.approve != nil && m.approve(j.Manifest.Version))
		if yes {
			if err := m.notifyUpdate(j.Manifest.Version, "installing"); err != nil {
				yes = false
			}
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if j.Guarded && (!m.guardEnabled() || m.upgradeGuard.jobID != id) || m.closing.Load() || !updateConsentValid(yes, automatic, m.config.Enabled, m.config.AutoUpgrade, revision, m.consentRevision, m.apiActive(api), m.apiActive(api)) {
			j.Status = "declined"
			j.Detail = "Local approval/notification unavailable, authorization changed, or USB disconnected"
			if saveErr := persistUpdateJob(m.root, j); saveErr != nil && j.Guarded {
				_ = m.retainGuardStorageLocked(api, j, []string{"awaiting_local_approval", "awaiting_auto_install", j.Status}, j.Status, j.Detail, saveErr)
				return
			}
			resetUpdateAPI(api, j)
			if j.Guarded {
				go m.guardReleaseJob(id)
			}
			return
		}
		fresh, e := validatedJob(id, m.version)
		if e != nil {
			j.Status = "failed"
			j.Detail = "Pre-launch verification failed"
			if saveErr := persistUpdateJob(m.root, j); saveErr != nil && j.Guarded {
				_ = m.retainGuardStorageLocked(api, j, []string{"awaiting_local_approval", "awaiting_auto_install", j.Status}, j.Status, j.Detail, saveErr)
				return
			}
			resetUpdateAPI(api, j)
			if j.Guarded {
				go m.guardReleaseJob(id)
			}
			return
		}
		j = fresh
		j.Status = "handoff"
		if saveErr := persistUpdateJob(m.root, j); saveErr != nil {
			if j.Guarded {
				_ = m.retainGuardStorageLocked(api, j, []string{"awaiting_local_approval", "awaiting_auto_install", "handoff"}, "failed", "Handoff persistence failed before worker launch", saveErr)
				return
			}
			resetUpdateAPI(api, j)
			if j.Guarded {
				go m.guardReleaseJob(id)
			}
			return
		}
		c := exec.Command(m.installed, "--update-worker", id, fmt.Sprint(os.Getpid()))
		inheritUpgradeGuard(c, j.Guarded)
		if j.Guarded {
			m.upgradeGuard.committed = true
			m.upgradeGuard.launchAttempted = true
		}
		if e = c.Start(); e != nil {
			j.Status = "failed"
			j.Detail = "Worker launch failed"
			if j.Guarded {
				// A missing durable PID is not positive proof no native process was
				// created. Preserve the launch boundary until exact recovery evidence.
				m.lastError = "Worker launch returned an error; native creation unconfirmed, reservation retained: " + e.Error()
				if saveErr := persistUpdateJob(m.root, j); saveErr != nil {
					m.lastError += "; persistence failed: " + saveErr.Error()
				}
				m.upgradeGuard.launchUnknown.Store(&guardRetrySnapshot{id: id, version: j.Manifest.Version, detail: m.lastError})
				return
			}
			persistUpdateJob(m.root, j)
			resetUpdateAPI(api, j)
			if j.Guarded {
				go m.guardReleaseJob(id)
			}
			return
		}
		workerPID := c.Process.Pid
		if j.Guarded {
			m.upgradeGuard.workerPID = uint32(workerPID)
			m.upgradeGuard.workerCreation, _ = processCreation(uint32(workerPID))
			m.upgradeGuard.workerExecutable = m.installed
		}
		c.Process.Release()
		workerReady := false
		for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
			var ack map[string]string
			if readRemote(filepath.Join(m.root, "worker-ready.json"), &ack) == nil && ack["id"] == id {
				validWorker := true
				if j.Guarded {
					var owner UpdateJob
					validWorker = ack["pid"] == fmt.Sprint(workerPID) && readRemote(filepath.Join(m.root, "job.json"), &owner) == nil && owner.ID == id && owner.OwnerPID == uint32(workerPID) && ack["creation"] == fmt.Sprint(owner.OwnerCreation)
					if validWorker {
						recorded, alive, err := recordedOwner(owner)
						validWorker = err == nil && recorded && alive
					}
				}
				if validWorker {
					workerReady = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !workerReady {
			if j.Guarded {
				// The spawned worker may still be alive or verifying bytes. Preserve the
				// reservation until its exact process exits; no concurrent settings.
				m.lastError = "Worker startup acknowledgement missing; previous version remains running, maintenance waits for its verified exit"
				return
			}
			j.Status = "failed"
			j.Detail = "Worker did not confirm readiness; current version remains running"
			if j.Guarded {
				m.upgradeGuard.committed = false
			}
			persistUpdateJob(m.root, j)
			resetUpdateAPI(api, j)
			if j.Guarded {
				go m.guardReleaseJob(id)
			}
			return
		}
		m.requested.Store(true)
		m.stop()
	}()
	return nil
}
func (m *RemoteManager) watch() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.reconcileGuardFailure()
			m.guardRefreshNormalAck()
			m.guardCandidateStatusSnapshot()
			m.mu.Lock()
			if m.guardEnabled() && m.runtimeStatus != nil {
				status, _ := m.runtimeStatus()
				m.guardStartupRecoveryAck(status)
			}
			if m.config.Enabled && !m.requested.Load() {
				if m.server != nil && (m.usbGUID() == "" || m.nativeGeneration != nil && !m.nativeGeneration()) {
					m.server.Close()
					m.server = nil
					m.nativeGeneration = nil
					remoteFirewall(false, "")
				}
				if m.config.Enabled && m.server == nil && m.usbGUID() != "" {
					if e := m.open(); e != nil {
						m.lastError = e.Error()
					} else {
						m.lastError = ""
					}
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *RemoteManager) Enabled() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.config.Enabled }
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
