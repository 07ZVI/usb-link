//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/contracts/coreipc"
)

const localRestartMutex = `Global\USBLinkLocalRestart-v1`

func readLocalRestart(root string) (localRestartJob, error) {
	b, e := coreProtectedReadBounded(filepath.Join(root, localRestartFile), false, true, 8192)
	if e != nil {
		return localRestartJob{}, e
	}
	return decodeRestartJob(b)
}
func writeLocalRestart(root string, j localRestartJob) error {
	if !j.valid() {
		return errors.New("LOCAL_RESTART_RECEIPT_INVALID")
	}
	if _, e := coreProtectedRead(root, true, false); e != nil {
		return e
	}
	if _, e := readLocalRestart(root); e != nil && !os.IsNotExist(e) {
		return e
	}
	if e := writeRemote(filepath.Join(root, localRestartFile), j); e != nil {
		return e
	}
	got, e := readLocalRestart(root)
	if e != nil || got != j {
		return errors.New("LOCAL_RESTART_RECEIPT_VERIFY_FAILED")
	}
	return nil
}
func restartNoInstallation(root string) error {
	if j, e := readLocalInstall(root, ""); e == nil {
		if !localInstallTerminal(j.Status) {
			return errors.New("LOCAL_RESTART_INSTALL_PENDING")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	t, p, e := readInstallationTransaction()
	if e != nil {
		return e
	}
	if p && t.Phase != InstallComplete && t.Phase != InstallRolledBack {
		return errors.New("LOCAL_RESTART_INSTALL_PENDING")
	}
	_, p, e = readCoreTransition()
	if e != nil {
		return e
	}
	if p {
		return errors.New("LOCAL_RESTART_TRANSITION_PENDING")
	}
	return nil
}
func restartBinding(j localRestartJob) error {
	b, e := CurrentCoreBinding()
	if e != nil || b != j.Binding || VerifyCoreExecutable(j.Binding.Executable) != nil {
		return errors.New("LOCAL_RESTART_SOURCE_CHANGED")
	}
	return nil
}
func readRestartConsent(root string, j localRestartJob) error {
	b, e := coreProtectedReadBounded(filepath.Join(root, localInstallConsentFile), false, true, 32768)
	if e != nil {
		return e
	}
	var c localInstallConsentReceipt
	if json.Unmarshal(b, &c) != nil || !c.Enabled || c.ParentPID != j.CorePID || c.ParentCreation != j.CoreCreation || c.Revision != j.Consent.Revision || c.TokenHash != j.Consent.TokenHash {
		return errors.New("LOCAL_RESTART_REVOKED")
	}
	return nil
}
func (m *RemoteManager) localRestartStatus() (LocalRestartStatus, error) {
	lease, e := acquireUpgradeJobMutex(localRestartMutex, 5000)
	if e != nil {
		return LocalRestartStatus{}, e
	}
	defer lease()
	j, e := reconcileLocalRestart(m.root)
	if os.IsNotExist(e) {
		return LocalRestartStatus{Phase: "idle"}, nil
	}
	if e != nil {
		return LocalRestartStatus{}, e
	}
	status := j.status()
	if j.Phase == "failed" {
		inspection := inspectLocalRestartTask(j)
		status.TaskInspection = &inspection
	}
	return status, nil
}

// The HTTP request only prepares a fixed task. The helper must claim it and
// pass the live core's consent gate before any running application is stopped.
func (m *RemoteManager) requestLocalRestart(id string) (LocalRestartStatus, error) {
	if !localArchiveHex(id, 32) || !m.localRemoteActive() {
		return LocalRestartStatus{}, errors.New("LOCAL_RESTART_REVOKED")
	}
	release, e := acquireUpgradeJobMutex(localInstallMutex, 0)
	if e != nil {
		return LocalRestartStatus{}, e
	}
	defer release()
	install, e := acquireUpgradeJobMutex(`Global\USBLinkInstallation-v1`, 0)
	if e != nil {
		return LocalRestartStatus{}, e
	}
	defer install()
	lease, e := acquireUpgradeJobMutex(localRestartMutex, 5000)
	if e != nil {
		return LocalRestartStatus{}, e
	}
	defer lease()
	if e = restartNoInstallation(m.root); e != nil {
		return LocalRestartStatus{}, e
	}
	if old, e := reconcileLocalRestart(m.root); e == nil {
		if old.ID == id {
			return old.status(), nil
		}
		if restartPreparedSupersedable(old) {
			old.Phase = "failed"
			old.Error = "LOCAL_RESTART_REVOKED"
			if e = writeLocalRestart(m.root, old); e != nil {
				return LocalRestartStatus{}, e
			}
		}
		if !restartTerminal(old.Phase) {
			return LocalRestartStatus{}, errors.New("LOCAL_RESTART_PENDING")
		}
		if old.HelperPID != 0 {
			exited, known := localInstallProcessExited(old.HelperPID, old.HelperCreation)
			if !known || !exited {
				return LocalRestartStatus{}, errors.New("LOCAL_RESTART_HELPER_ACTIVE")
			}
		}
		if restartRetainUnverified(old) {
			if e = retainLocalRestart(m.root, old); e != nil {
				return LocalRestartStatus{}, e
			}
		} else if e = restartTask(&old, "delete"); e != nil {
			old.Phase = "failed"
			old.Error = "LOCAL_RESTART_TASK_CLEANUP_FAILED"
			old.CleanupDiagnostic = restartDiagnostic("delete", "apartment", e)
			if saveErr := writeLocalRestart(m.root, old); saveErr != nil {
				return LocalRestartStatus{}, saveErr
			}
			return LocalRestartStatus{}, e
		}
	} else if !os.IsNotExist(e) {
		return LocalRestartStatus{}, e
	}
	b, e := CurrentCoreBinding()
	if e != nil || b.Executable != m.installed || VerifyCoreServiceProcess(uint32(os.Getpid())) != nil {
		return LocalRestartStatus{}, errors.New("LOCAL_RESTART_SOURCE_CHANGED")
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0 || session == 0xffffffff {
		return LocalRestartStatus{}, errors.New("LOCAL_RESTART_OWNER_UNAVAILABLE")
	}
	var tok windows.Token
	if e = windows.WTSQueryUserToken(session, &tok); e != nil {
		return LocalRestartStatus{}, e
	}
	identity, e := shareTokenIdentity(tok)
	tok.Close()
	if e != nil || identity.SID != b.OwnerSID || identity.Session != session {
		return LocalRestartStatus{}, errors.New("LOCAL_RESTART_OWNER_UNAVAILABLE")
	}
	created, e := processCreation(uint32(os.Getpid()))
	if e != nil {
		return LocalRestartStatus{}, e
	}
	m.mu.Lock()
	j := localRestartJob{Schema: 1, ID: id, Binding: b, Session: session, CorePID: uint32(os.Getpid()), CoreCreation: created, Consent: localRestartConsent{Revision: m.consentRevision, TokenHash: localInstallConsent(m.config.Token)}, Phase: "prepared"}
	m.mu.Unlock()
	if !m.localRemoteActive() || readRestartConsent(m.root, j) != nil {
		return LocalRestartStatus{}, errors.New("LOCAL_RESTART_REVOKED")
	}
	if e = writeLocalRestart(m.root, j); e != nil {
		return LocalRestartStatus{}, e
	}
	fail := func(operation, stage string, cause error) (LocalRestartStatus, error) {
		j.Diagnostic = restartDiagnostic(operation, stage, cause)
		j.Phase = "failed"
		j.Error = "LOCAL_RESTART_TASK_FAILED"
		if j.TaskSHA != "" {
			if err := restartTask(&j, "delete"); err != nil {
				j.Error = "LOCAL_RESTART_TASK_CLEANUP_FAILED"
				j.CleanupDiagnostic = restartDiagnostic("delete", "apartment", err)
			}
		}
		_ = writeLocalRestart(m.root, j)
		return j.status(), errors.New(j.Error)
	}
	if e = restartTask(&j, "create"); e != nil {
		return fail("create", "apartment", e)
	}
	if e = writeLocalRestart(m.root, j); e != nil {
		return fail("prepare", "receipt_save", e)
	}
	if !m.localRemoteActive() || readRestartConsent(m.root, j) != nil || restartBinding(j) != nil {
		return fail("prepare", "pre_submit", errors.New("LOCAL_RESTART_REVOKED"))
	}
	if e = restartTask(&j, "run"); e != nil {
		return fail("run", "apartment", e)
	}
	return j.status(), nil
}

// Admission is serialized with OFF receipt revocation, but never holds the
// manager/network lock. After this single admission, shutdown's own revocation
// must not erase the helper's authority to finish the fixed restart.
func (m *RemoteManager) AuthorizeLocalRestart(id, sid string, session, pid uint32, creation uint64) error {
	lease, e := acquireUpgradeJobMutex(localRestartMutex, 5000)
	if e != nil {
		return e
	}
	defer lease()
	m.localRemote.consent.mu.Lock()
	defer m.localRemote.consent.mu.Unlock()
	j, e := readLocalRestart(m.root)
	if e != nil {
		return e
	}
	if !m.localRemote.desired.Load() || !m.localRemote.admitted.Load() || m.closing.Load() || !restartAdmissionMatches(j, id, sid, session, pid, creation, uint32(os.Getpid())) {
		return errors.New("LOCAL_RESTART_REVOKED")
	}
	if e = restartBinding(j); e != nil {
		return e
	}
	if e = readRestartConsent(m.root, j); e != nil {
		return e
	}
	if e = restartTask(&j, "verify"); e != nil {
		return e
	}
	if !m.localRemote.desired.Load() || !m.localRemote.admitted.Load() || m.closing.Load() {
		return errors.New("LOCAL_RESTART_REVOKED")
	}
	j.Admitted = true
	return writeLocalRestart(m.root, j)
}

func restartCall(ctx context.Context, method string, payload any, oldPID uint32) (coreipc.Response, uint32, error) {
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return coreipc.Response{}, 0, e
	}
	b, e := json.Marshal(payload)
	if e != nil {
		return coreipc.Response{}, 0, e
	}
	var server uint32
	r, e := coreipc.Call(ctx, coreipc.Request{Version: 1, ID: hex.EncodeToString(id[:]), Method: method, Payload: b}, func(pid uint32) error {
		if oldPID != 0 && oldPID != pid {
			return errors.New("LOCAL_RESTART_CORE_CHANGED")
		}
		if e := VerifyCoreServiceProcess(pid); e != nil {
			return e
		}
		server = pid
		return nil
	})
	if e == nil && r.Problem != "" {
		e = errors.New("LOCAL_RESTART_CORE_REQUEST_FAILED")
	}
	return r, server, e
}
func restartWait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(200 * time.Millisecond):
		return nil
	}
}

//go:noinline
func RunLocalRemoteRestart(id string) (result error) {
	if !localArchiveHex(id, 32) {
		return errors.New("LOCAL_RESTART_ID_INVALID")
	}
	root, e := remoteRoot()
	if e != nil {
		return e
	}
	release, e := acquireUpgradeJobMutex(localInstallMutex, 5000)
	if e != nil {
		return e
	}
	defer release()
	install, e := acquireUpgradeJobMutex(`Global\USBLinkInstallation-v1`, 5000)
	if e != nil {
		return e
	}
	defer install()
	lease, e := acquireUpgradeJobMutex(localRestartMutex, 5000)
	if e != nil {
		return e
	}
	j, e := readLocalRestart(root)
	if e != nil {
		lease()
		return e
	}
	if j.ID != id || j.Phase != "prepared" || j.Admitted || localInstallInteractiveOwner(localInstallJob{OwnerSID: j.Binding.OwnerSID, Session: j.Session}) != nil || restartBinding(j) != nil {
		lease()
		return errors.New("LOCAL_RESTART_PRECONDITION_FAILED")
	}
	pin, e := PinCoreSelfSource(j.Binding.Executable)
	if e != nil {
		lease()
		return e
	}
	defer pin()
	j.HelperPID = uint32(os.Getpid())
	j.HelperCreation, e = processCreation(j.HelperPID)
	if e != nil {
		lease()
		return e
	}
	j.Phase = "running"
	e = writeLocalRestart(root, j)
	lease()
	if e != nil {
		return e
	}
	// Every later write must still own the exact claimed receipt. No helper may
	// overwrite a newer request, even after a delayed native operation returns.
	save := func() error {
		lock, e := acquireUpgradeJobMutex(localRestartMutex, 5000)
		if e != nil {
			return e
		}
		defer lock()
		old, e := readLocalRestart(root)
		if e != nil || old.ID != j.ID || old.HelperPID != j.HelperPID || old.HelperCreation != j.HelperCreation {
			return errors.New("LOCAL_RESTART_CLAIM_CHANGED")
		}
		j.Admitted = j.Admitted || old.Admitted
		return writeLocalRestart(root, j)
	}
	failure := "LOCAL_RESTART_HELPER_FAILED"
	defer func() {
		if result != nil {
			j.Phase = "failed"
			j.Error = failure
			j.Diagnostic = restartDiagnostic("helper", "helper", result)
		}
		if e := restartTask(&j, "delete"); e != nil {
			j.Phase = "failed"
			j.Error = "LOCAL_RESTART_TASK_CLEANUP_FAILED"
			j.CleanupDiagnostic = restartDiagnostic("delete", "apartment", e)
			result = errors.New(j.Error)
		}
		if e := save(); e != nil {
			result = errors.New("LOCAL_RESTART_RECEIPT_WRITE_FAILED")
		}
	}()
	if restartNoInstallation(root) != nil || readRestartConsent(root, j) != nil {
		failure = "LOCAL_RESTART_REVOKED"
		return errors.New(failure)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Pin the old process handle, not just a PID or a temporarily missing pipe.
	old, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, j.CorePID)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(old)
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(old, &c, &x, &k, &u) != nil || uint64(c.HighDateTime)<<32|uint64(c.LowDateTime) != j.CoreCreation {
		return errors.New("LOCAL_RESTART_CORE_CHANGED")
	}
	failure = "LOCAL_RESTART_REVOKED"
	if _, _, e = restartCall(ctx, "action", map[string]string{"action": "restart-program", "id": id}, j.CorePID); e != nil {
		return e
	}
	admitted, e := readLocalRestart(root)
	if e != nil || !restartAdmissionReceipt(j, admitted) {
		return errors.New("LOCAL_RESTART_ADMISSION_UNCONFIRMED")
	}
	j = admitted
	failure = "LOCAL_RESTART_EXIT_FAILED"
	for {
		r, _, err := restartCall(ctx, "snapshot", struct{}{}, j.CorePID)
		if err != nil {
			return err
		}
		var s struct {
			Display struct {
				Desktop struct {
					Exit struct {
						ID        string `json:"request_id"`
						Phase     string `json:"phase"`
						UIDrained bool   `json:"ui_drained"`
					} `json:"program_exit"`
				} `json:"desktop"`
			} `json:"display"`
		}
		if json.Unmarshal(r.Payload, &s) != nil {
			return errors.New("LOCAL_RESTART_SNAPSHOT_INVALID")
		}
		if s.Display.Desktop.Exit.ID != id {
			return errors.New("LOCAL_RESTART_EXIT_CHANGED")
		}
		if s.Display.Desktop.Exit.Phase == "failed" {
			return errors.New("LOCAL_RESTART_EXIT_FAILED")
		}
		if s.Display.Desktop.Exit.Phase == "ready" && s.Display.Desktop.Exit.UIDrained {
			break
		}
		if e = restartWait(ctx); e != nil {
			failure = "LOCAL_RESTART_EXIT_TIMEOUT"
			return e
		}
	}
	j.Phase = "ready"
	if e = save(); e != nil {
		return e
	}
	if _, _, e = restartCall(ctx, "action", map[string]string{"action": "exit-program-commit", "id": id}, j.CorePID); e != nil {
		return e
	}
	for {
		state, err := windows.WaitForSingleObject(old, 0)
		if err != nil {
			return err
		}
		if state == windows.WAIT_OBJECT_0 {
			break
		}
		if state != uint32(windows.WAIT_TIMEOUT) {
			return errors.New("LOCAL_RESTART_WAIT_FAILED")
		}
		if e = restartWait(ctx); e != nil {
			failure = "LOCAL_RESTART_EXIT_TIMEOUT"
			return e
		}
	}
	failure = "LOCAL_RESTART_SOURCE_CHANGED"
	if e = restartBinding(j); e != nil {
		return e
	}
	j.Phase = "starting"
	if e = save(); e != nil {
		return e
	}
	failure = "LOCAL_RESTART_START_FAILED"
	if e = StartCoreService(); e != nil {
		return e
	}
	failure = "LOCAL_RESTART_CORE_UNCONFIRMED"
	for {
		r, pid, err := restartCall(ctx, "snapshot", struct{}{}, 0)
		if err == nil && pid != j.CorePID && restartCoreSnapshotReadable(r.Payload, buildinfo.Version) {
			j.CoreReadable = true
			break
		}
		if e = restartWait(ctx); e != nil {
			return e
		}
	}
	failure = "LOCAL_RESTART_LOGIN_FAILED"
	if e = restartBinding(j); e != nil {
		return e
	}
	cmd := exec.Command(j.Binding.Executable, "--resident")
	cmd.Dir = filepath.Dir(j.Binding.Executable)
	if e = cmd.Start(); e != nil {
		return e
	}
	_ = cmd.Process.Release()
	j.LoginRequested = true
	j.Phase = "completed"
	j.Error = ""
	return nil
}

// Caller owns the restart receipt mutex. Unknown process state is retained,
// never mistaken for termination. Failed receipts are not replayable.
func reconcileLocalRestart(root string) (localRestartJob, error) {
	j, e := readLocalRestart(root)
	if e != nil {
		return j, e
	}
	exited, known := false, false
	if j.HelperPID != 0 {
		exited, known = localInstallProcessExited(j.HelperPID, j.HelperCreation)
	}
	if !restartAbandoned(j, exited, known) {
		return j, nil
	}
	j.Phase = "failed"
	j.Error = "LOCAL_RESTART_HELPER_FAILED"
	if e = writeLocalRestart(root, j); e != nil {
		return j, e
	}
	if e = restartTask(&j, "delete"); e != nil {
		j.Error = "LOCAL_RESTART_TASK_CLEANUP_FAILED"
		j.CleanupDiagnostic = restartDiagnostic("delete", "apartment", e)
		if e = writeLocalRestart(root, j); e != nil {
			return j, e
		}
	}
	return j, nil
}

// Quarantine only the failed, never-claimed receipt. Missing task identity is
// not authority to adopt/delete it. A later task still requires the current ID.
func retainLocalRestart(root string, j localRestartJob) error {
	if !j.valid() || !restartRetainUnverified(j) {
		return errors.New("LOCAL_RESTART_RETENTION_UNCONFIRMED")
	}
	if _, e := coreProtectedRead(root, true, false); e != nil {
		return e
	}
	path := filepath.Join(root, "local-restart-retained-"+j.ID+".json")
	read := func() (localRestartJob, bool, error) {
		b, e := coreProtectedReadBounded(path, false, true, 8192)
		if os.IsNotExist(e) {
			return localRestartJob{}, false, nil
		}
		if e != nil {
			return localRestartJob{}, false, e
		}
		old, e := decodeRestartJob(b)
		return old, true, e
	}
	count := func() (int, error) {
		entries, e := os.ReadDir(root)
		if e != nil {
			return 0, e
		}
		n := 0
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "local-restart-retained-") {
				n++
			}
		}
		return n, nil
	}
	return retainRestartReceipt(j, read, count, func(value localRestartJob) error { return writeRemote(path, value) })
}
