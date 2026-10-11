//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"time"
)

func validatedJob(id, current string) (UpdateJob, error) {
	var j UpdateJob
	root, e := remoteRoot()
	if e != nil {
		return j, e
	}
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return j, fmt.Errorf("invalid job id")
	}
	if e = readRemote(filepath.Join(root, "job.json"), &j); e != nil || j.ID != id {
		return j, fmt.Errorf("job unavailable")
	}
	dir := filepath.Dir(j.Target)
	if filepath.Dir(dir) != root || !strings.HasPrefix(filepath.Base(dir), "release-") || filepath.Base(j.Target) != "release.exe" || noReparse(dir) != nil || Verify(j.Old) != nil {
		return j, fmt.Errorf("job path ownership changed")
	}
	r, e := readReceipt(filepath.Dir(j.Old))
	if e != nil || (current != "" && r.Version != current) {
		return j, fmt.Errorf("previous version mismatch")
	}
	if e = j.Manifest.Verify(remoteupdate.PublisherKey(), r.Version, time.Now()); e != nil {
		return j, e
	}
	sum, e := fileHash(j.Target)
	if e != nil || sum != j.Manifest.SHA256 {
		return j, fmt.Errorf("staged file changed")
	}
	return j, nil
}
func ValidateRemoteLaunch(id, version string) error {
	j, e := validatedJob(id, "")
	if e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil || Verify(self) != nil || j.Manifest.Version != version || j.Status != "starting" {
		return fmt.Errorf("remote launch not authorized")
	}
	sum, e := fileHash(self)
	if e != nil || sum != j.Manifest.SHA256 {
		return fmt.Errorf("remote executable changed")
	}
	return nil
}
func RemoteReady(id, version string) error {
	if e := ValidateRemoteLaunch(id, version); e != nil {
		return e
	}
	if coreUpgradeRequired() {
		j, e := validatedJob(id, "")
		if e != nil || verifyCoreCandidateJob(j) != nil {
			return fmt.Errorf("CORE_REMOTE_CANDIDATE_CHANGED")
		}
	}
	root, e := remoteRoot()
	if e != nil {
		return e
	}
	ack := map[string]string{"id": id, "version": version}
	if upgradeGuardInherited() {
		m := activeUpgradeManager.Load()
		if m == nil || m.recoveryOnly {
			return fmt.Errorf("recovery maintenance is not normal USB readiness")
		}
		if !remoteUSBHealthy() {
			return fmt.Errorf("Mac USB peer and receiver readiness unverified")
		}
		ack["usb_state"] = "verified"
		ack["pid"] = fmt.Sprint(os.Getpid())
		ack["observed_at_unix_nano"] = fmt.Sprint(time.Now().UnixNano())
		m.upgradeGuard.startupNormal.Store(true)
	}
	return writeRemote(filepath.Join(root, "ready.json"), ack)
}
func installRemoteBinary(j UpdateJob) (string, error) {
	root, e := protectedRoot(false)
	if e != nil {
		return "", e
	}
	dir := filepath.Join(root, j.Manifest.Version)
	target := filepath.Join(dir, BinaryName)
	if _, e = os.Stat(dir); e == nil {
		if Verify(target) != nil {
			return "", fmt.Errorf("existing candidate changed")
		}
		sum, e := fileHash(target)
		if e != nil || sum != j.Manifest.SHA256 {
			return "", fmt.Errorf("candidate version conflicts")
		}
		return target, nil
	} else if !os.IsNotExist(e) {
		return "", e
	}
	stage, e := os.MkdirTemp(root, "install-")
	if e != nil {
		return "", e
	}
	path := filepath.Join(stage, BinaryName)
	defer func() { os.Remove(path); os.Remove(filepath.Join(stage, "ownership.json")); os.Remove(stage) }()
	in, e := os.Open(j.Target)
	if e != nil {
		return "", e
	}
	defer in.Close()
	out, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", e
	}
	e = remoteupdate.VerifyBinary(io.TeeReader(in, out), j.Manifest)
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e != nil {
		return "", e
	}
	if ce != nil {
		return "", ce
	}
	if e = writeRemote(filepath.Join(stage, "ownership.json"), Receipt{ProductID, j.Manifest.Version, j.Manifest.SHA256}); e != nil {
		return "", e
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(stage), windows.StringToUTF16Ptr(dir), windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return "", e
	}
	return target, Verify(target)
}

// RunUpdateWorker is an owned installed executable with fixed arguments. It
// waits for graceful cleanup, never kills the old process or runs shell input.
func RunUpdateWorker(id, pidText, current string) error {
	j, e := validatedJob(id, current)
	if e != nil || j.Status != "handoff" {
		return fmt.Errorf("unauthorized worker")
	}
	self, _ := os.Executable()
	if !strings.EqualFold(self, j.Old) || Verify(self) != nil || !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("worker identity rejected")
	}
	coreMode, coreError := usingCoreExecutable(j.Old)
	if coreError != nil {
		return coreError
	}
	if coreMode && !j.Guarded {
		return fmt.Errorf("service upgrade requires recorded guarded owner and startup health")
	}
	root, _ := remoteRoot()
	save := func(status, detail string) error {
		next := j
		next.Status, next.Detail = status, detail
		err := persistUpdateJob(root, next)
		if j.Guarded && err != nil {
			return err
		}
		j = next
		return nil
	}
	recordFailure := func(reason string) error {
		j.CandidateFailure = captureCandidateFailure(root, j, reason)
		return save(j.Status, j.Detail)
	}
	pid, e := strconv.ParseUint(pidText, 10, 32)
	if e != nil || pid == 0 {
		return fmt.Errorf("invalid parent")
	}
	if j.Guarded {
		creation, err := processCreation(uint32(pid))
		if err != nil || j.OwnerPID != uint32(pid) || creation != j.OwnerCreation || !strings.EqualFold(j.OwnerExecutable, j.Old) {
			return fmt.Errorf("recorded parent owner changed")
		}
	}
	parent, e := ownedProcess(uint32(pid))
	if e != nil {
		if err := save("failed", "Parent process could not be verified"); err != nil {
			return err
		}
		return e
	}
	defer windows.CloseHandle(parent)
	if j.Guarded {
		if e = adoptUpgradeWorker(root, &j); e != nil {
			return e
		}
	}
	workerAck := map[string]string{"id": id}
	if j.Guarded {
		workerAck["pid"] = fmt.Sprint(os.Getpid())
		workerAck["creation"] = fmt.Sprint(j.OwnerCreation)
	}
	if e = writeRemote(filepath.Join(root, "worker-ready.json"), workerAck); e != nil {
		return e
	}
	if state, e := windows.WaitForSingleObject(parent, 180000); e != nil || state != windows.WAIT_OBJECT_0 {
		if err := save("failed", "Previous process did not finish cleanup; no new version started"); err != nil {
			return err
		}
		return fmt.Errorf("parent cleanup timeout")
	}
	// Recheck all signed bytes after the old process has exited.
	fresh, verifyErr := validatedJob(id, current)
	if !j.Guarded {
		j = fresh
	}
	if verifyErr != nil || fresh.Status != "handoff" {
		if err := save("failed", "Verification after cleanup failed"); err != nil {
			return err
		}
		if verifyErr != nil {
			return verifyErr
		}
		return fmt.Errorf("handoff state changed")
	}
	j = fresh
	target, e := installRemoteBinary(j)
	if e != nil {
		return rollbackPrevious(j, save, "Candidate installation failed; restarting previous version")
	}
	if err := save("starting", ""); err != nil {
		return err
	}
	var candidatePID int
	var done chan error
	if coreMode {
		if e = InstallCoreService(target); e != nil {
			if se := recordFailure("CORE_INSTALL_FAILED"); se != nil {
				return se
			}
			return rollbackPrevious(j, save, "Owned core service upgrade failed; restoring previous service")
		}
		pid, err := coreProcess(target)
		if err != nil {
			return err
		}
		candidatePID = int(pid)
		h, err := ownedProcess(pid)
		if err != nil {
			return err
		}
		done = make(chan error, 1)
		go func() {
			defer windows.CloseHandle(h)
			state, err := windows.WaitForSingleObject(h, windows.INFINITE)
			if err == nil && state != windows.WAIT_OBJECT_0 {
				err = fmt.Errorf("core process wait failed")
			}
			done <- err
		}()
	} else {
		c := exec.Command(target, "--remote-install", id)
		inheritUpgradeGuard(c, j.Guarded)
		if e = c.Start(); e != nil {
			if se := recordFailure("CANDIDATE_LAUNCH_FAILED"); se != nil {
				return se
			}
			return rollbackPrevious(j, save, "New executable failed to start; restarting previous version")
		}
		candidatePID = c.Process.Pid
		done = make(chan error, 1)
		go func() { done <- c.Wait() }()
	}
	if j.Guarded {
		j.CandidatePID = uint32(candidatePID)
		j.CandidateExecutable = target
		j.CandidateCreation, e = processCreation(j.CandidatePID)
		if e != nil {
			return fmt.Errorf("candidate identity unavailable: %w", e)
		}
		if e = persistUpdateJob(root, j); e != nil {
			return e
		}
	}
	var childHandle windows.Handle
	if j.Guarded {
		childHandle, e = ownedProcess(j.CandidatePID)
		if e != nil {
			return fmt.Errorf("candidate liveness unavailable: %w", e)
		}
		defer windows.CloseHandle(childHandle)
		var created, exited, kernel, user windows.Filetime
		if windows.GetProcessTimes(childHandle, &created, &exited, &kernel, &user) != nil || uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) != j.CandidateCreation {
			return fmt.Errorf("candidate liveness identity changed")
		}
	}
	deadline := time.NewTimer(180 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var readyAt time.Time
	var health remoteupdate.StartupTracker
	for {
		select {
		case <-done:
			if e = recordFailure("EXIT_BEFORE_HEALTH"); e != nil {
				return e
			}
			return rollbackPrevious(j, save, "New executable exited before health confirmation; restarting previous version")
		case <-ticker.C:
			var ack map[string]string
			ackValid := readRemote(filepath.Join(root, "ready.json"), &ack) == nil && ack["id"] == id && ack["version"] == j.Manifest.Version
			if j.Guarded {
				ackValid = ackValid && remoteupdate.StartupAckMatches(ack, id, j.Manifest.Version, candidatePID, time.Now())
				state, err := windows.WaitForSingleObject(childHandle, 0)
				if err != nil || state != windows.WAIT_OBJECT_0 && state != uint32(windows.WAIT_TIMEOUT) {
					return fmt.Errorf("candidate liveness cannot be confirmed; no parallel rollback")
				}
				decision := health.Observe(time.Now(), remoteupdate.StartupEvidence{MatchingAck: ackValid, USBState: ack["usb_state"], Alive: state == uint32(windows.WAIT_TIMEOUT)}, false)
				if decision == remoteupdate.StartupRollback {
					if e = recordFailure("EXIT_BEFORE_HEALTH"); e != nil {
						return e
					}
					return rollbackPrevious(j, save, "Exact candidate process exited before startup health confirmation; restarting previous version")
				}
				if decision == remoteupdate.StartupComplete {
					if coreMode {
						if e = refreshCoreWorkerEntries(j, target, j.Manifest.Version); e != nil {
							if se := recordFailure("OWNED_LOGIN_ENTRIES_FAILED"); se != nil {
								return se
							}
							stop := requestCoreCandidateStop(j)
							stop.Close()
							select {
							case <-done:
								return rollbackPrevious(j, save, "Owned login entries failed after USB confirmation; restoring previous service")
							case <-time.After(90 * time.Second):
								return save("manual_recovery_required", "Login entry update failed and core shutdown is unconfirmed; no parallel rollback")
							}
						}
					}
					return save("complete", "Signed version deployed; normal USB readiness confirmed continuously")
				}
				if decision == remoteupdate.StartupRecovery {
					return save("deployed_recovery_required", "Signed version installed and deployed process remained running; ordinary USB remains unavailable, maintenance transport availability is reported separately")
				}
			} else if ackValid {
				if readyAt.IsZero() {
					readyAt = time.Now()
				}
				if time.Since(readyAt) >= 5*time.Second {
					if err := save("complete", "New version initialized and remained running; USB reconnect is verified separately"); err != nil {
						return err
					}
					return nil
				}
			}
		case <-deadline.C:
			if e = recordFailure("HEALTH_TIMEOUT"); e != nil {
				return e
			}
			var stop *UpgradeStop
			if coreMode {
				stop = requestCoreCandidateStop(j)
			} else if j.Guarded {
				stop = requestRecordedCandidateStop(j)
			} else {
				stop = RequestPreviousStop()
			}
			stop.Close()
			select {
			case <-done:
				return rollbackPrevious(j, save, "Startup confirmation timed out; previous version restored after graceful exit")
			case <-time.After(90 * time.Second):
				if err := save("manual_recovery_required", "New version did not confirm startup or finish graceful shutdown; no forced termination"); err != nil {
					return err
				}
				return fmt.Errorf("new process did not stop")
			}
		}
	}
}
func rollbackPrevious(j UpdateJob, save func(string, string) error, reason string) error {
	if !j.Guarded {
		_ = save("rollback", reason)
		return restartPrevious(j)
	}
	return remoteupdate.RunRollback(reason, save, func() remoteupdate.RollbackResult {
		if _, present, bindingError := readCoreBinding(); bindingError != nil {
			return remoteupdate.RollbackResult{Status: "rollback_failed", Detail: "Core service binding unverified; no parallel owner started", Err: bindingError}
		} else if present {
			if err := InstallCoreService(j.Old); err != nil {
				return remoteupdate.RollbackResult{Status: "rollback_failed", Detail: "Owned previous service could not restore; receipts retained", Err: err}
			}
			if _, err := coreProcess(j.Old); err != nil {
				return remoteupdate.RollbackResult{Status: "rollback_failed", Detail: "Restored service process identity unproven", Err: err}
			}
			receipt, err := readReceipt(filepath.Dir(j.Old))
			if err != nil {
				return remoteupdate.RollbackResult{Status: "rollback_failed", Detail: "Previous installation version unproven", Err: err}
			}
			if err = refreshCoreWorkerEntries(j, j.Old, receipt.Version); err != nil {
				return remoteupdate.RollbackResult{Status: "rollback_failed", Detail: "Previous service running but owned login entries could not restore", Err: err}
			}
			return remoteupdate.RollbackResult{Status: "rollback_running", Detail: "Previous verified core service running; USB recovery not yet verified"}
		}
		if err := Verify(j.Old); err != nil {
			return remoteupdate.RollbackResult{Status: "rollback_failed", Detail: "Previous executable ownership changed; no unverified binary launched", Err: err}
		}
		c := exec.Command(j.Old, "--resident")
		inheritUpgradeGuard(c, true)
		if err := c.Start(); err != nil {
			return remoteupdate.RollbackResult{Status: "rollback_failed", Detail: "Previous verified executable could not start; manual recovery required", Err: err}
		}
		done := make(chan error, 1)
		go func() { done <- c.Wait() }()
		select {
		case err := <-done:
			if err == nil {
				err = fmt.Errorf("previous process exited")
			}
			return remoteupdate.RollbackResult{Status: "rollback_failed", Detail: "Previous version exited during startup; USB recovery unavailable", Err: err}
		case <-time.After(5 * time.Second):
			return remoteupdate.RollbackResult{Status: "rollback_running", Detail: "Previous verified process restarted and remained running; USB recovery has not been verified", Err: nil}
		}
	})
}
func restartPrevious(j UpdateJob) error {
	if Verify(j.Old) != nil {
		return fmt.Errorf("rollback executable changed")
	}
	c := exec.Command(j.Old, "--resident")
	if e := c.Start(); e != nil {
		return e
	}
	return c.Process.Release()
}
