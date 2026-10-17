//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/app/remoteupdate"
)

const localInstallJournal = "local-install-job.json"
const localInstallConsentFile = "local-remote-consent.json"
const localInstallMutex = `Global\USBLinkLocalInstall-v1`
const LocalRemoteElevateArgument = "--local-remote-elevate"
const LocalRemoteDispatchArgument = "--local-remote-dispatch"
const LocalRemoteInstallArgument = "--local-remote-install"

type localInstallJob struct {
	ID                 string                `json:"id"`
	Manifest           remoteupdate.Manifest `json:"manifest"`
	PreviousVersion    string                `json:"previous_version"`
	OwnerSID           string                `json:"owner_sid"`
	Session            uint32                `json:"session"`
	Consent            string                `json:"consent_sha256"`
	Revision           uint64                `json:"revision"`
	Deadline           int64                 `json:"approval_deadline"`
	Status             string                `json:"status"`
	Detail             string                `json:"detail,omitempty"`
	BrokerPID          uint32                `json:"broker_pid,omitempty"`
	BrokerCreation     uint64                `json:"broker_creation,omitempty"`
	DispatcherPID      uint32                `json:"dispatcher_pid,omitempty"`
	DispatcherCreation uint64                `json:"dispatcher_creation,omitempty"`
	InstallerPID       uint32                `json:"installer_pid,omitempty"`
	InstallerCreation  uint64                `json:"installer_creation,omitempty"`
	UIStatus           string                `json:"ui_status,omitempty"`
}

type localInstallConsentReceipt struct {
	Enabled        bool   `json:"enabled"`
	ParentPID      uint32 `json:"parent_pid"`
	ParentCreation uint64 `json:"parent_creation"`
	Revision       uint64 `json:"revision"`
	TokenHash      string `json:"token_hash"`
}

// Caller holds m.mu. This receipt is only current-process consent, never
// restored by startup as permission to open the network listener.
func (m *RemoteManager) localRemoteSetConsent(enabled bool, epochs ...uint64) error {
	r := localInstallConsentReceipt{}
	if enabled {
		if len(epochs) != 1 {
			return fmt.Errorf("LOCAL_REMOTE_CONSENT_EPOCH_REQUIRED")
		}
		r.Enabled = true
		r.ParentPID = uint32(os.Getpid())
		r.Revision = m.consentRevision
		r.TokenHash = localInstallConsent(m.config.Token)
		var e error
		r.ParentCreation, e = processCreation(r.ParentPID)
		if e != nil || r.TokenHash == "" {
			return fmt.Errorf("LOCAL_REMOTE_CONSENT_IDENTITY_UNAVAILABLE")
		}
	}
	var epoch uint64
	if enabled {
		epoch = epochs[0]
	}
	return m.localRemote.consent.write(enabled, epoch, m.localRemote.desired.Load, func() error {
		return writeRemote(filepath.Join(m.root, localInstallConsentFile), r)
	})
}

func localInstallPath(root, id string) string {
	return filepath.Join(root, "local-release-"+id, "setup.exe")
}

func readLocalInstall(root, id string) (localInstallJob, error) {
	var j localInstallJob
	b, e := coreProtectedReadBounded(filepath.Join(root, localInstallJournal), false, true, 32768)
	if e != nil {
		return j, e
	}
	if json.Unmarshal(b, &j) != nil || !localInstallIDValid(j.ID) || id != "" && id != j.ID || !validPreparedUserSID(j.OwnerSID) || j.Session == 0 || j.Session == 0xffffffff {
		return j, fmt.Errorf("LOCAL_REMOTE_JOB_INVALID")
	}
	return j, nil
}

func writeLocalInstall(root string, j localInstallJob) error {
	return writeRemote(filepath.Join(root, localInstallJournal), j)
}

func verifyLocalInstall(root string, j localInstallJob) error {
	if e := j.Manifest.Verify(remoteupdate.PublisherKey(), j.PreviousVersion, time.Now()); e != nil {
		return e
	}
	p := localInstallPath(root, j.ID)
	if _, e := coreProtectedRead(filepath.Dir(p), true, false); e != nil {
		return e
	}
	if _, e := coreProtectedRead(p, false, false); e != nil {
		return e
	}
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	return remoteupdate.VerifyBinary(f, j.Manifest)
}

func localInstallCurrentConsent(root string, j localInstallJob) error {
	var c localInstallConsentReceipt
	b, e := coreProtectedReadBounded(filepath.Join(root, localInstallConsentFile), false, true, 32768)
	if e != nil {
		return e
	}
	if json.Unmarshal(b, &c) != nil || c.Revision != j.Revision || !localInstallAuthorized(c.Enabled, c.TokenHash, j.Consent, j.Deadline, time.Now()) {
		return fmt.Errorf("LOCAL_REMOTE_CONSENT_EXPIRED_OR_REVOKED")
	}
	created, e := processCreation(c.ParentPID)
	if e != nil || created == 0 || created != c.ParentCreation {
		return fmt.Errorf("LOCAL_REMOTE_CONSENT_OWNER_EXITED")
	}
	return nil
}

func (m *RemoteManager) localInstallConsentMatches(j localInstallJob) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config.Enabled && m.consentRevision == j.Revision && localInstallConsent(m.config.Token) == j.Consent && j.Consent != "" && !m.closing.Load()
}

func (m *RemoteManager) localRemoteStage(manifest remoteupdate.Manifest, body io.Reader) (string, error) {
	if !m.localRemoteActive() {
		return "", fmt.Errorf("LOCAL_REMOTE_NOT_ACTIVE")
	}
	if e := manifest.Verify(remoteupdate.PublisherKey(), m.version, time.Now()); e != nil {
		return "", e
	}
	release, e := acquireUpgradeJobMutex(localInstallMutex, 5000)
	if e != nil {
		return "", e
	}
	defer release()
	if old, e := readLocalInstall(m.root, ""); e == nil {
		if !localInstallTerminal(old.Status) {
			return "", fmt.Errorf("LOCAL_REMOTE_JOB_PENDING: %s", old.ID)
		}
		if e = cleanupLocalInstallTerminal(m.root, old); e != nil {
			return "", e
		}
	} else if !os.IsNotExist(e) {
		return "", e
	}
	entries, e := os.ReadDir(m.root)
	if e != nil {
		return "", e
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "local-release-") {
			return "", fmt.Errorf("LOCAL_REMOTE_STAGED_BYTES_RECOVERY_REQUIRED")
		}
	}
	binding, e := CurrentCoreBinding()
	if e != nil || !strings.EqualFold(binding.Executable, m.installed) {
		return "", fmt.Errorf("LOCAL_REMOTE_CORE_CHANGED")
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0 || session == 0xffffffff {
		return "", fmt.Errorf("LOCAL_REMOTE_USER_NOT_LOGGED_ON")
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return "", e
	}
	j := localInstallJob{ID: hex.EncodeToString(nonce[:]), Manifest: manifest, PreviousVersion: m.version, OwnerSID: binding.OwnerSID, Session: session, Status: "staged"}
	m.mu.Lock()
	j.Consent = localInstallConsent(m.config.Token)
	j.Revision = m.consentRevision
	m.mu.Unlock()
	if j.Consent == "" {
		return "", fmt.Errorf("LOCAL_REMOTE_CONSENT_MISSING")
	}
	p := localInstallPath(m.root, j.ID)
	if e = os.Mkdir(filepath.Dir(p), 0700); e != nil {
		return "", e
	}
	saved := false
	defer func() {
		if !saved {
			_ = os.Remove(p)
			_ = os.Remove(filepath.Dir(p))
		}
	}()
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", e
	}
	e = remoteupdate.VerifyBinary(io.TeeReader(body, f), manifest)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return "", e
	}
	if !m.localRemoteActive() || !m.localInstallConsentMatches(j) {
		return "", fmt.Errorf("LOCAL_REMOTE_CONSENT_CHANGED")
	}
	// A failed atomic publication may have reached disk. Preserve those signed
	// bytes and let the next stage detect the orphan, rather than deleting proof.
	saved = true
	if e = writeLocalInstall(m.root, j); e != nil {
		return "", e
	}
	return j.ID, nil
}

func (m *RemoteManager) localRemoteStatus() any {
	j, e := readLocalInstall(m.root, "")
	if os.IsNotExist(e) {
		return map[string]string{"status": "idle"}
	}
	if e != nil {
		return map[string]string{"status": "manual_recovery_required", "detail": "LOCAL_REMOTE_JOURNAL_UNREADABLE"}
	}
	return map[string]any{"id": j.ID, "version": j.Manifest.Version, "status": j.Status, "detail": j.Detail, "current_version": m.version, "ui_status": j.UIStatus}
}

func (m *RemoteManager) localRemotePendingCancelID() string {
	j, e := readLocalInstall(m.root, "")
	if e == nil && localInstallCancelable(j.Status) {
		return j.ID
	}
	return ""
}

// Poll without waiting for an installer. Only proven terminal jobs release the
// server slot; unknown process or transaction state stays visible for recovery.
func (m *RemoteManager) localRemoteReconcile() string {
	release, e := acquireUpgradeJobMutex(localInstallMutex, 0)
	if e != nil {
		return ""
	}
	defer release()
	j, e := readLocalInstall(m.root, "")
	if e != nil {
		return ""
	}
	if localInstallTerminal(j.Status) {
		return j.ID
	}
	if j.Status == "awaiting_local_admin" && j.Deadline <= time.Now().Unix() {
		j.Status = "cancelled"
		j.Detail = "Local administrator approval expired"
		if writeLocalInstall(m.root, j) == nil {
			return j.ID
		}
		return ""
	}
	if j.Status != "dispatching" && j.Status != "installing" {
		return ""
	}
	dead, known := localInstallProcessExited(j.InstallerPID, j.InstallerCreation)
	if !known || !dead {
		return ""
	}
	t, present, e := readInstallationTransaction()
	if e != nil {
		return ""
	}
	if present && t.Next.SHA == j.Manifest.SHA256 && t.Next.Version == j.Manifest.Version {
		switch t.Phase {
		case InstallComplete:
			j.Status = "complete"
			j.Detail = "Complete App installation accepted"
		case InstallRolledBack:
			j.Status = "failed"
			j.Detail = "Installation transaction restored previous version"
		default:
			j.Status = "manual_recovery_required"
			j.Detail = "Installer exited with an unfinished installation transaction"
		}
	} else if j.Status == "dispatching" {
		j.Status = "failed"
		j.Detail = "Installer exited before installation transaction"
	} else {
		j.Status = "manual_recovery_required"
		j.Detail = "Installation outcome requires inspection"
	}
	if writeLocalInstall(m.root, j) == nil && localInstallTerminal(j.Status) {
		return j.ID
	}
	return ""
}

func localInstallProcessExited(pid uint32, creation uint64) (exited, known bool) {
	if pid == 0 || creation == 0 {
		return false, false
	}
	h, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e == windows.ERROR_INVALID_PARAMETER {
		return true, true
	}
	if e != nil {
		return false, false
	}
	defer windows.CloseHandle(h)
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &x, &k, &u) != nil {
		return false, false
	}
	if uint64(c.HighDateTime)<<32|uint64(c.LowDateTime) != creation {
		return true, true
	}
	s, e := windows.WaitForSingleObject(h, 0)
	return s == windows.WAIT_OBJECT_0, e == nil && (s == windows.WAIT_OBJECT_0 || s == uint32(windows.WAIT_TIMEOUT))
}

func (m *RemoteManager) localRemoteCancel(id string) error {
	if !localInstallIDValid(id) {
		return fmt.Errorf("LOCAL_REMOTE_JOB_INVALID")
	}
	release, e := acquireUpgradeJobMutex(localInstallMutex, 5000)
	if e != nil {
		return e
	}
	defer release()
	j, e := readLocalInstall(m.root, id)
	if e != nil {
		return e
	}
	if !localInstallCancelable(j.Status) {
		return fmt.Errorf("LOCAL_REMOTE_INSTALL_ALREADY_HANDED_OFF")
	}
	j.Status = "cancelled"
	j.Detail = "Cancelled before installer handoff"
	return writeLocalInstall(m.root, j)
}

func (m *RemoteManager) localRemoteApply(id string) error {
	if !localInstallIDValid(id) || !m.localRemoteActive() {
		return fmt.Errorf("LOCAL_REMOTE_NOT_ACTIVE")
	}
	release, e := acquireUpgradeJobMutex(localInstallMutex, 5000)
	if e != nil {
		return e
	}
	defer release()
	j, e := readLocalInstall(m.root, id)
	if e != nil {
		return e
	}
	if j.Status != "staged" || !m.localInstallConsentMatches(j) {
		return fmt.Errorf("LOCAL_REMOTE_STAGE_OR_CONSENT_CHANGED")
	}
	if e = verifyLocalInstall(m.root, j); e != nil {
		return e
	}
	b, e := CurrentCoreBinding()
	if e != nil || b.OwnerSID != j.OwnerSID || !strings.EqualFold(b.Executable, m.installed) || VerifyCoreExecutable(b.Executable) != nil {
		return fmt.Errorf("LOCAL_REMOTE_CORE_CHANGED")
	}
	var user windows.Token
	if e = windows.WTSQueryUserToken(j.Session, &user); e != nil {
		return fmt.Errorf("LOCAL_REMOTE_USER_TOKEN_UNAVAILABLE: %w", e)
	}
	defer user.Close()
	identity, e := shareTokenIdentity(user)
	if e != nil || identity.SID != j.OwnerSID || identity.Session != j.Session || windows.WTSGetActiveConsoleSessionId() != j.Session {
		return fmt.Errorf("LOCAL_REMOTE_USER_CHANGED")
	}
	var env *uint16
	if e = windows.CreateEnvironmentBlock(&env, user, false); e != nil {
		return e
	}
	defer windows.DestroyEnvironmentBlock(env)
	if !m.localRemoteActive() || !m.localInstallConsentMatches(j) {
		return fmt.Errorf("LOCAL_REMOTE_CONSENT_CHANGED")
	}
	j.Status = "awaiting_local_admin"
	j.Deadline = time.Now().Add(2 * time.Minute).Unix()
	if e = writeLocalInstall(m.root, j); e != nil {
		return e
	}
	// Session 0's default window station must never be inherited by the UAC
	// helper. The bound user's desktop and environment are explicit.
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: windows.StringToUTF16Ptr(`winsta0\default`)}
	var process windows.ProcessInformation
	line := windows.ComposeCommandLine([]string{b.Executable, LocalRemoteElevateArgument, j.ID})
	if e = windows.CreateProcessAsUser(user, windows.StringToUTF16Ptr(b.Executable), windows.StringToUTF16Ptr(line), nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, env, windows.StringToUTF16Ptr(filepath.Dir(b.Executable)), &startup, &process); e != nil {
		j.Status = "failed"
		j.Detail = "LOCAL_REMOTE_USER_LAUNCH_FAILED"
		return errors.Join(e, writeLocalInstall(m.root, j))
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	j.BrokerPID = process.ProcessId
	j.BrokerCreation, e = processCreation(j.BrokerPID)
	if e != nil {
		return e
	} // Preserve uncertain launch, never start another helper.
	return writeLocalInstall(m.root, j)
}

// LaunchLocalRemoteElevation has no caller-selected executable or command.
// The unprivileged helper cannot read the protected job; the elevated dispatch
// verifies it before any package is executed.
//
//go:noinline
func LaunchLocalRemoteElevation(id string) error {
	if !localInstallIDValid(id) {
		return fmt.Errorf("LOCAL_REMOTE_JOB_INVALID")
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(self), windows.StringToUTF16Ptr(LocalRemoteDispatchArgument+" "+id), nil, 1)
}

func localInstallInteractiveOwner(j localInstallJob) error {
	t := windows.GetCurrentProcessToken()
	i, e := shareTokenIdentity(t)
	if e != nil || !t.IsElevated() || i.SID != j.OwnerSID || i.Session != j.Session || i.Session == 0 || windows.WTSGetActiveConsoleSessionId() != j.Session {
		return fmt.Errorf("LOCAL_REMOTE_INTERACTIVE_OWNER_REQUIRED")
	}
	return nil
}

//go:noinline
func DispatchLocalRemoteInstall(id string) error {
	if !localInstallIDValid(id) {
		return fmt.Errorf("LOCAL_REMOTE_JOB_INVALID")
	}
	release, e := acquireUpgradeJobMutex(localInstallMutex, 5000)
	if e != nil {
		return e
	}
	defer release()
	root, e := remoteRoot()
	if e != nil {
		return e
	}
	j, e := readLocalInstall(root, id)
	if e != nil {
		return e
	}
	if j.Status != "awaiting_local_admin" {
		return fmt.Errorf("LOCAL_REMOTE_HANDOFF_CHANGED")
	}
	if e = localInstallInteractiveOwner(j); e != nil {
		return e
	}
	if e = localInstallCurrentConsent(root, j); e != nil {
		return e
	}
	self, e := os.Executable()
	b, be := CurrentCoreBinding()
	if e != nil || be != nil || b.OwnerSID != j.OwnerSID || !strings.EqualFold(b.Executable, self) || VerifyCoreExecutable(self) != nil {
		return fmt.Errorf("LOCAL_REMOTE_DISPATCH_SOURCE_CHANGED")
	}
	if e = verifyLocalInstall(root, j); e != nil {
		return e
	}
	j.Status = "dispatching"
	j.DispatcherPID = uint32(os.Getpid())
	j.DispatcherCreation, e = processCreation(j.DispatcherPID)
	if e != nil {
		return e
	}
	if e = writeLocalInstall(root, j); e != nil {
		return e
	}
	cmd := exec.Command(localInstallPath(root, id), LocalRemoteInstallArgument, id)
	cmd.Dir = filepath.Dir(localInstallPath(root, id))
	if e = cmd.Start(); e != nil {
		j.Status = "failed"
		j.Detail = "LOCAL_REMOTE_PACKAGE_LAUNCH_FAILED"
		return errors.Join(e, writeLocalInstall(root, j))
	}
	j.InstallerPID = uint32(cmd.Process.Pid)
	j.InstallerCreation, e = processCreation(j.InstallerPID)
	_ = cmd.Process.Release()
	if e != nil {
		return e
	}
	return writeLocalInstall(root, j)
}

func waitLocalInstallHelper(pid uint32, creation uint64) error {
	if pid == 0 || creation == 0 {
		return fmt.Errorf("LOCAL_REMOTE_HELPER_IDENTITY_MISSING")
	}
	h, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e == windows.ERROR_INVALID_PARAMETER {
		return nil
	}
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	var c, x, k, u windows.Filetime
	if e = windows.GetProcessTimes(h, &c, &x, &k, &u); e != nil {
		return e
	}
	if uint64(c.HighDateTime)<<32|uint64(c.LowDateTime) != creation {
		return nil
	} // Original exited; never act on reused PID.
	s, e := windows.WaitForSingleObject(h, 10000)
	if e != nil || s != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("LOCAL_REMOTE_HELPER_STILL_RUNNING")
	}
	return nil
}

// RunLocalRemoteInstall validates this signed installer and executes only its
// compiled-in complete App transaction. The caller supplies no path or version.
//
//go:noinline
func RunLocalRemoteInstall(id, version string, install func(context.Context) (string, error)) error {
	if !localInstallIDValid(id) || install == nil {
		return fmt.Errorf("LOCAL_REMOTE_JOB_INVALID")
	}
	release, e := acquireUpgradeJobMutex(localInstallMutex, 5000)
	if e != nil {
		return e
	}
	defer release()
	root, e := remoteRoot()
	if e != nil {
		return e
	}
	j, e := readLocalInstall(root, id)
	if e != nil {
		return e
	}
	if j.Status != "dispatching" || j.Manifest.Version != version {
		return fmt.Errorf("LOCAL_REMOTE_PACKAGE_VERSION_CHANGED")
	}
	created, ce := processCreation(uint32(os.Getpid()))
	if ce != nil || j.InstallerPID != uint32(os.Getpid()) || created != j.InstallerCreation {
		return fmt.Errorf("LOCAL_REMOTE_INSTALLER_IDENTITY_CHANGED")
	}
	if e = localInstallInteractiveOwner(j); e != nil {
		return e
	}
	if e = localInstallCurrentConsent(root, j); e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil || !strings.EqualFold(self, localInstallPath(root, id)) {
		return fmt.Errorf("LOCAL_REMOTE_PACKAGE_SOURCE_CHANGED")
	}
	if e = verifyLocalInstall(root, j); e != nil {
		return e
	}
	// Both helpers run from App. Wait for their exact processes before the
	// transaction replaces App; never kill or infer exit from a reused PID.
	if e = waitLocalInstallHelper(j.BrokerPID, j.BrokerCreation); e != nil {
		return e
	}
	if e = waitLocalInstallHelper(j.DispatcherPID, j.DispatcherCreation); e != nil {
		return e
	}
	if e = localInstallCurrentConsent(root, j); e != nil {
		return e
	}
	j.Status = "installing"
	if e = writeLocalInstall(root, j); e != nil {
		return e
	}
	_, e = install(context.Background())
	if e != nil {
		j.Status = "failed"
		j.Detail = e.Error()
		if len(j.Detail) > 512 {
			j.Detail = j.Detail[:512]
		}
		if t, present, readError := readInstallationTransaction(); readError != nil || present && t.Phase != InstallComplete && t.Phase != InstallRolledBack {
			j.Status = "manual_recovery_required"
		}
	} else {
		j.Status = "complete"
		j.Detail = "Complete App installation accepted"
	}
	if saveError := writeLocalInstall(root, j); e != nil || saveError != nil {
		if e == nil {
			return &LocalRemoteUILaunchError{saveError}
		}
		return errors.Join(e, saveError)
	}
	if e = launchLocalInstalledUI(j); e != nil {
		j.UIStatus = "launch_failed"
		return &LocalRemoteUILaunchError{errors.Join(e, writeLocalInstall(root, j))}
	}
	j.UIStatus = "launch_requested"
	if e = writeLocalInstall(root, j); e != nil {
		return &LocalRemoteUILaunchError{e}
	}
	return nil
}

type LocalRemoteUILaunchError struct{ Cause error }

func (e *LocalRemoteUILaunchError) Error() string {
	return "LOCAL_REMOTE_INSTALLED_UI_UNCONFIRMED: " + e.Cause.Error()
}
func (e *LocalRemoteUILaunchError) Unwrap() error { return e.Cause }

func launchLocalInstalledUI(j localInstallJob) error {
	p, e := CurrentApplication()
	if e != nil {
		return e
	}
	r, e := readReceipt(filepath.Dir(p))
	if e != nil || r.Version != j.Manifest.Version || r.SHA != j.Manifest.SHA256 || VerifyCoreExecutable(p) != nil {
		return fmt.Errorf("LOCAL_REMOTE_INSTALLED_UI_SOURCE_CHANGED")
	}
	b, e := CurrentCoreBinding()
	if e != nil || b.OwnerSID != j.OwnerSID || !strings.EqualFold(b.Executable, p) || b.SHA256 != j.Manifest.SHA256 {
		return fmt.Errorf("LOCAL_REMOTE_INSTALLED_UI_BINDING_CHANGED")
	}
	cmd := exec.Command(p)
	cmd.Dir = filepath.Dir(p)
	if e = cmd.Start(); e != nil {
		return e
	}
	return cmd.Process.Release()
}
