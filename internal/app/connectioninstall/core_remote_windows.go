//go:build windows && amd64

package connectioninstall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/contracts/coreipc"
	"sync"
	"sync/atomic"
	"time"
)

var coreUpgradeGuard atomic.Bool
var coreRemoteJobID atomic.Pointer[string]
var coreBootstrapHealth struct {
	sync.Mutex
	readiness coreBootstrapReadiness
}
var errCoreBootstrapSettling = errors.New("CORE_BOOTSTRAP_HEALTH_SETTLING")

// ErrRemoteMaintenanceUnavailable means the maintenance folder or its job
// could not be read at all; candidate verdicts are distinct errors.
var ErrRemoteMaintenanceUnavailable = errors.New("CORE_REMOTE_MAINTENANCE_UNAVAILABLE")

func resetCoreBootstrapHealth() {
	coreBootstrapHealth.Lock()
	coreBootstrapHealth.readiness = coreBootstrapReadiness{}
	coreBootstrapHealth.Unlock()
}

// SCM does not inherit a worker environment. Recover only the signed, protected
// live worker job whose candidate is this exact owned service executable.
func CoreRemoteLaunch(version string) (string, error) {
	if _, bound := BoundCoreOwnerSID(); !bound {
		return "", fmt.Errorf("CORE_SERVICE_CONTEXT_REQUIRED")
	}
	root, e := remoteRoot()
	if e != nil {
		return "", fmt.Errorf("%w: %v", ErrRemoteMaintenanceUnavailable, e)
	}
	var job UpdateJob
	e = readRemote(filepath.Join(root, "job.json"), &job)
	if os.IsNotExist(e) {
		return "", nil
	}
	if e != nil {
		return "", fmt.Errorf("%w: %v", ErrRemoteMaintenanceUnavailable, e)
	}
	self, e := os.Executable()
	if e != nil {
		return "", e
	}
	if job.Status != "starting" {
		if !coreFailedCandidateRecorded(job.Status, job.CandidatePID, job.CandidateCreation) || !strings.EqualFold(job.CandidateExecutable, self) {
			return "", nil
		}
		failed, e := validatedJob(job.ID, "")
		b, be := CurrentCoreBinding()
		hash, he := fileHash(self)
		receipt, re := readReceipt(filepath.Dir(self))
		if e != nil || be != nil || he != nil || re != nil || !strings.EqualFold(b.Executable, self) || b.SHA256 != hash || receipt.Version != version {
			return "", fmt.Errorf("CORE_REMOTE_FAILED_CANDIDATE_UNPROVEN")
		}
		if coreFailedCandidateRecorded(failed.Status, failed.CandidatePID, failed.CandidateCreation) && strings.EqualFold(failed.CandidateExecutable, self) && failed.Manifest.Version == version && failed.Manifest.SHA256 == hash {
			return "", fmt.Errorf("CORE_REMOTE_FAILED_CANDIDATE_PRESERVED")
		}
		return "", nil
	}
	j, e := validatedJob(job.ID, "")
	if e != nil || j.Manifest.Version != version {
		return "", fmt.Errorf("CORE_REMOTE_JOB_INVALID")
	}
	hash, e := fileHash(self)
	if e != nil || hash != j.Manifest.SHA256 {
		return "", fmt.Errorf("CORE_REMOTE_CANDIDATE_CHANGED")
	}
	if !j.Guarded {
		// The first legacy bootstrap remains the candidate owner; a service
		// never manufactures a guarded acknowledgement for that old worker.
		return "", nil
	}
	known, alive, e := recordedOwner(j)
	if e != nil || !known || !alive {
		return "", fmt.Errorf("CORE_REMOTE_WORKER_UNVERIFIED")
	}
	workerReceipt, e := readReceipt(filepath.Dir(j.OwnerExecutable))
	if e != nil {
		return "", fmt.Errorf("CORE_REMOTE_WORKER_CAPABILITY_UNPROVEN")
	}
	coreUpgradeGuard.Store(true)
	if !coreWorkerSupported(workerReceipt.Version) {
		return "", nil
	}
	b, e := CurrentCoreBinding()
	if e != nil || !strings.EqualFold(b.Executable, self) {
		return "", fmt.Errorf("CORE_REMOTE_SERVICE_CHANGED")
	}
	coreUpgradeGuard.Store(true)
	id := j.ID
	coreRemoteJobID.Store(&id)
	return j.ID, nil
}

func coreUpgradeRequired() bool { _, bound := BoundCoreOwnerSID(); return bound }
func startupAckJobID() string {
	if coreUpgradeRequired() {
		if id := coreRemoteJobID.Load(); id != nil {
			return *id
		}
		return ""
	}
	if len(os.Args) == 3 && os.Args[1] == "--remote-install" {
		return os.Args[2]
	}
	return ""
}
func verifyCoreCandidateJob(j UpdateJob) error {
	if !coreUpgradeRequired() {
		return nil
	}
	self, e := os.Executable()
	creation, ce := processCreation(uint32(os.Getpid()))
	if e != nil || ce != nil || j.CandidatePID != uint32(os.Getpid()) || j.CandidateCreation != creation || !strings.EqualFold(j.CandidateExecutable, self) || VerifyCoreServiceProcess(uint32(os.Getpid())) != nil {
		return fmt.Errorf("CORE_REMOTE_CANDIDATE_CHANGED")
	}
	return nil
}
func coreProcess(exe string) (uint32, error) {
	m, e := mgr.Connect()
	if e != nil {
		return 0, e
	}
	defer m.Disconnect()
	s, b, e := ownedCoreService(m)
	if e != nil {
		return 0, e
	}
	defer s.Close()
	p, e := s.Query()
	if e != nil || p.State != svc.Running || p.ProcessId == 0 || !strings.EqualFold(b.Executable, exe) {
		return 0, fmt.Errorf("CORE_SERVICE_PID_UNPROVEN")
	}
	return p.ProcessId, VerifyCoreServiceProcess(p.ProcessId)
}
func usingCoreExecutable(exe string) (bool, error) {
	b, present, e := readCoreBinding()
	if e != nil {
		return false, e
	}
	if !present {
		return false, nil
	}
	if !strings.EqualFold(b.Executable, exe) {
		return false, fmt.Errorf("CORE_SERVICE_UPGRADE_OWNER_CHANGED")
	}
	_, e = CurrentCoreBinding()
	return e == nil, e
}
func requestCoreCandidateStop(j UpdateJob) *UpgradeStop {
	r := &UpgradeStop{processes: map[uint32]windows.Handle{}}
	pid, e := coreProcess(j.CandidateExecutable)
	if e != nil || pid != j.CandidatePID {
		r.Error = "CORE_CANDIDATE_IDENTITY_CHANGED"
		return r
	}
	h, e := ownedProcess(pid)
	if e != nil {
		r.Error = e.Error()
		return r
	}
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &x, &k, &u) != nil || uint64(c.HighDateTime)<<32|uint64(c.LowDateTime) != j.CandidateCreation {
		windows.CloseHandle(h)
		r.Error = "CORE_CANDIDATE_CREATION_CHANGED"
		return r
	}
	r.processes[pid] = h
	if e = StopCoreService(); e != nil {
		r.Error = e.Error()
		return r
	}
	r.Requested = 1
	return r
}

// The first service migration still belongs to the legacy worker's interactive
// bootstrap PID. Only a signed live candidate and fresh authenticated core USB
// snapshot may acknowledge that exact old protocol; UI presence is insufficient.
func ConfirmCoreBootstrap(ctx context.Context, id, version string) (result error) {
	defer func() {
		if result != nil && !errors.Is(result, errCoreBootstrapSettling) {
			resetCoreBootstrapHealth()
		}
	}()
	if ValidateRemoteLaunch(id, version) != nil {
		return fmt.Errorf("CORE_BOOTSTRAP_LAUNCH_UNAUTHORIZED")
	}
	j, e := validatedJob(id, "")
	if e != nil || j.Status != "starting" {
		return fmt.Errorf("CORE_BOOTSTRAP_JOB_CHANGED")
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	b, e := CurrentCoreBinding()
	if e != nil || !strings.EqualFold(b.Executable, self) || b.SHA256 != j.Manifest.SHA256 {
		return fmt.Errorf("CORE_BOOTSTRAP_SERVICE_CHANGED")
	}
	owner, e := windows.GetCurrentProcessToken().GetTokenUser()
	session, se := shareTokenDWORD(windows.GetCurrentProcessToken(), windows.TokenSessionId)
	if e != nil || se != nil || owner.User.Sid.String() != b.OwnerSID || session == 0 {
		return fmt.Errorf("CORE_BOOTSTRAP_USER_CHANGED")
	}
	if j.Guarded {
		known, alive, e := recordedOwner(j)
		if e != nil || !known || !alive {
			return fmt.Errorf("CORE_BOOTSTRAP_WORKER_UNVERIFIED")
		}
		created, e := processCreation(uint32(os.Getpid()))
		if e != nil || j.CandidatePID != uint32(os.Getpid()) || j.CandidateCreation != created || !strings.EqualFold(j.CandidateExecutable, self) {
			return fmt.Errorf("CORE_BOOTSTRAP_CANDIDATE_CHANGED")
		}
		receipt, e := readReceipt(filepath.Dir(j.OwnerExecutable))
		if e != nil || coreWorkerSupported(receipt.Version) {
			return fmt.Errorf("CORE_BOOTSTRAP_LEGACY_WORKER_REQUIRED")
		}
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	request := coreipc.Request{Version: 1, ID: hex.EncodeToString(nonce[:]), Method: "snapshot", Payload: json.RawMessage(`{}`)}
	var corePID uint32
	reply, e := coreipc.Call(ctx, request, func(pid uint32) error {
		if e := VerifyCoreServiceProcess(pid); e != nil {
			return e
		}
		corePID = pid
		return nil
	})
	if e != nil || reply.Problem != "" {
		return fmt.Errorf("CORE_BOOTSTRAP_HEALTH_UNAVAILABLE")
	}
	var proof struct {
		Version string `json:"version"`
		Healthy bool   `json:"remote_usb_healthy"`
	}
	if json.Unmarshal(reply.Payload, &proof) != nil || proof.Version != version || !proof.Healthy || corePID == 0 || VerifyCoreServiceProcess(corePID) != nil {
		return fmt.Errorf("CORE_BOOTSTRAP_USB_UNCONFIRMED")
	}
	fresh, e := validatedJob(id, "")
	if e != nil || fresh.Status != "starting" || jobIdentity(fresh) != jobIdentity(j) || fresh.CandidatePID != j.CandidatePID || fresh.CandidateCreation != j.CandidateCreation || fresh.CandidateExecutable != j.CandidateExecutable || ValidateRemoteLaunch(id, version) != nil {
		return fmt.Errorf("CORE_BOOTSTRAP_JOB_CHANGED")
	}
	candidateCreation, ce := processCreation(uint32(os.Getpid()))
	coreCreation, pe := processCreation(corePID)
	if ce != nil || pe != nil || VerifyCoreServiceProcess(corePID) != nil {
		return fmt.Errorf("CORE_BOOTSTRAP_PROCESS_CHANGED")
	}
	identity := coreBootstrapIdentity{Job: id, Hash: j.Manifest.SHA256, CandidatePID: uint32(os.Getpid()), CandidateCreation: candidateCreation, CorePID: corePID, CoreCreation: coreCreation}
	coreBootstrapHealth.Lock()
	ready := coreBootstrapHealth.readiness.observe(time.Now(), identity, true)
	coreBootstrapHealth.Unlock()
	if !ready {
		return errCoreBootstrapSettling
	}
	ack := map[string]string{"id": id, "version": version}
	if j.Guarded {
		ack["usb_state"] = "verified"
		ack["pid"] = fmt.Sprint(os.Getpid())
		ack["observed_at_unix_nano"] = fmt.Sprint(time.Now().UnixNano())
	}
	root, e := remoteRoot()
	if e != nil {
		return e
	}
	return writeRemote(filepath.Join(root, "ready.json"), ack)
}

// CoreBootstrapPending is observation only. Only the exact signed legacy job
// and this live bootstrap may end its repeated health acknowledgements.
func CoreBootstrapPending(id, version string) (bool, error) {
	j, e := validatedJob(id, "")
	if e != nil || j.Manifest.Version != version {
		return false, fmt.Errorf("CORE_BOOTSTRAP_JOB_CHANGED")
	}
	self, e := os.Executable()
	b, be := CurrentCoreBinding()
	if e != nil || be != nil || !strings.EqualFold(b.Executable, self) || b.SHA256 != j.Manifest.SHA256 {
		return false, fmt.Errorf("CORE_BOOTSTRAP_SERVICE_CHANGED")
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	session, se := shareTokenDWORD(windows.GetCurrentProcessToken(), windows.TokenSessionId)
	if e != nil || se != nil || session == 0 || user.User.Sid.String() != b.OwnerSID {
		return false, fmt.Errorf("CORE_BOOTSTRAP_USER_CHANGED")
	}
	if j.Guarded {
		creation, e := processCreation(uint32(os.Getpid()))
		receipt, re := readReceipt(filepath.Dir(j.OwnerExecutable))
		if e != nil || re != nil || coreWorkerSupported(receipt.Version) || j.CandidatePID != uint32(os.Getpid()) || j.CandidateCreation != creation || !strings.EqualFold(j.CandidateExecutable, self) {
			return false, fmt.Errorf("CORE_BOOTSTRAP_CANDIDATE_CHANGED")
		}
	}
	if _, e = coreProcess(self); e != nil {
		return false, e
	}
	switch j.Status {
	case "complete":
		return false, nil
	case "starting":
		if j.Guarded {
			known, alive, e := recordedOwner(j)
			if e != nil || !known || !alive {
				return false, fmt.Errorf("CORE_BOOTSTRAP_WORKER_UNVERIFIED")
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("CORE_BOOTSTRAP_JOB_NOT_COMPLETE")
	}
}

// Only the actual recorded SYSTEM worker can reconcile login entries after
// startup health or rollback. A user token is used solely for its explicit
// Programs folder; an absent/different user never resolves SYSTEM's profile.
func refreshCoreWorkerEntries(j UpdateJob, target, version string) (result error) {
	unlock, e := coreLifecycleLock()
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	if coreipc.RequireSystemService() != nil {
		return fmt.Errorf("CORE_WORKER_SYSTEM_REQUIRED")
	}
	fresh, e := validatedJob(j.ID, "")
	self, se := os.Executable()
	creation, ce := processCreation(uint32(os.Getpid()))
	if e != nil || se != nil || ce != nil || !fresh.Guarded || fresh.OwnerPID != uint32(os.Getpid()) || fresh.OwnerCreation != creation || !strings.EqualFold(fresh.OwnerExecutable, self) || !strings.EqualFold(fresh.Old, j.Old) || fresh.Manifest.SHA256 != j.Manifest.SHA256 || fresh.Manifest.Version != j.Manifest.Version || fresh.Status != "starting" && fresh.Status != "rollback" {
		return fmt.Errorf("CORE_WORKER_JOB_CHANGED")
	}
	b, e := CurrentCoreBinding()
	r, re := readReceipt(filepath.Dir(target))
	if e != nil || re != nil || !strings.EqualFold(b.Executable, target) || r.Version != version || VerifyCoreExecutable(target) != nil {
		return fmt.Errorf("CORE_WORKER_TARGET_CHANGED")
	}
	if fresh.Status == "starting" {
		if version != fresh.Manifest.Version || b.SHA256 != fresh.Manifest.SHA256 || fresh.CandidatePID == 0 || fresh.CandidateCreation == 0 {
			return fmt.Errorf("CORE_WORKER_TARGET_CHANGED")
		}
		pid, e := coreProcess(target)
		created, ce := processCreation(pid)
		if e != nil || ce != nil || pid != fresh.CandidatePID || created != fresh.CandidateCreation {
			return fmt.Errorf("CORE_WORKER_CANDIDATE_CHANGED")
		}
	} else if !strings.EqualFold(target, fresh.Old) {
		return fmt.Errorf("CORE_WORKER_ROLLBACK_TARGET_CHANGED")
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0 || session == 0xffffffff {
		return fmt.Errorf("CORE_WORKER_USER_NOT_LOGGED_ON")
	}
	var user windows.Token
	if e = windows.WTSQueryUserToken(session, &user); e != nil {
		return fmt.Errorf("CORE_WORKER_USER_TOKEN_UNAVAILABLE")
	}
	defer user.Close()
	identity, e := shareTokenIdentity(user)
	if e != nil || validateShareIdentity(shareIdentity{SID: b.OwnerSID, Session: session}, identity) != nil {
		return fmt.Errorf("CORE_WORKER_USER_CHANGED")
	}
	programs, e := user.KnownFolderPath(windows.FOLDERID_Programs, 0)
	if e != nil {
		return e
	}
	if _, e = coreProcess(target); e != nil {
		return e
	}
	if e = Register(target, version); e != nil {
		return e
	}
	if e = updateShortcutAtPrograms(target, false, programs); e != nil {
		return e
	}
	got, e := CurrentCoreBinding()
	if e != nil || got != b || windows.WTSGetActiveConsoleSessionId() != session {
		return fmt.Errorf("CORE_WORKER_ENTRIES_UNCONFIRMED")
	}
	return nil
}
