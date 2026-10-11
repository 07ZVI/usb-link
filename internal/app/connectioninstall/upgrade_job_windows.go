//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"time"
	"unsafe"
)

func processCreation(pid uint32) (uint64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var created, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &created, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}
func recordedOwner(j UpdateJob) (bool, bool, error) {
	if j.OwnerPID == 0 || j.OwnerCreation == 0 {
		return false, false, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, j.OwnerPID)
	if err == windows.ERROR_INVALID_PARAMETER {
		return true, false, nil
	}
	if err != nil {
		return false, false, err
	}
	defer windows.CloseHandle(h)
	var created, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &created, &exit, &kernel, &user); err != nil {
		return false, false, err
	}
	if uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) != j.OwnerCreation {
		return true, false, nil
	}
	var path [32768]uint16
	n := uint32(len(path))
	if windows.QueryFullProcessImageName(h, 0, &path[0], &n) != nil || !strings.EqualFold(windows.UTF16ToString(path[:n]), j.OwnerExecutable) || Verify(windows.UTF16ToString(path[:n])) != nil {
		return false, false, fmt.Errorf("update owner executable unverified")
	}
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return false, false, err
	}
	return true, state == uint32(windows.WAIT_TIMEOUT), nil
}
func jobIdentity(j UpdateJob) remoteupdate.JobIdentity {
	return remoteupdate.JobIdentity{ID: j.ID, Status: j.Status, Executable: strings.ToLower(j.OwnerExecutable), Guarded: j.Guarded, PID: j.OwnerPID, Creation: j.OwnerCreation}
}
func writeUpgradeJob(root string, j UpdateJob) error { return writeJobOwned(root, j, nil, false) }
func writeJobOwned(root string, j UpdateJob, expectedOwner *remoteupdate.JobIdentity, deadOwnerTransition bool) (result error) {
	unlock, err := upgradeJobLock()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unlock()) }()
	var current UpdateJob
	readErr := readRemote(filepath.Join(root, "job.json"), &current)
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if expectedOwner != nil && (readErr != nil || jobIdentity(current) != *expectedOwner) {
		return fmt.Errorf("upgrade transition owner changed")
	}

	if deadOwnerTransition {
		self, err := os.Executable()
		if err != nil || Verify(self) != nil {
			return fmt.Errorf("recovery writer executable unverified")
		}
		// This exceptional transition runs under the same cross-process mutex as
		// the compare/write. It cannot impersonate a live or unknown old owner.
		if readErr != nil || !current.Guarded || current.ID != j.ID || jobIdentity(current).PID != j.OwnerPID || jobIdentity(current).Creation != j.OwnerCreation || jobIdentity(current).Executable != jobIdentity(j).Executable || !remoteupdate.UpdateInFlight(current.Status) || j.Status != "interrupted" {
			return fmt.Errorf("dead-owner recovery transition changed")
		}
		known, alive, err := recordedOwner(current)
		if err != nil || !known || alive {
			return fmt.Errorf("previous owner still active or unverified")
		}
		detail := j.Detail
		j = current
		j.Status, j.Detail = "interrupted", detail
		if current.Status == "starting" || current.Status == "manual_recovery_required" {
			child := current
			child.OwnerPID = current.CandidatePID
			child.OwnerCreation = current.CandidateCreation
			child.OwnerExecutable = current.CandidateExecutable
			known, alive, err = recordedOwner(child)
			if err != nil || !known || alive {
				return fmt.Errorf("candidate still active or unverified")
			}
		}
	} else if j.Guarded {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		creation, err := processCreation(uint32(os.Getpid()))
		if err != nil {
			return err
		}
		if !remoteupdate.OrdinaryWriterAllowed(jobIdentity(j), uint32(os.Getpid()), creation, strings.ToLower(self)) || Verify(self) != nil {
			return fmt.Errorf("actual writing process does not own guarded job")
		}
	}
	// Existing legacy-only jobs retain their transition semantics. The same
	// cross-process lock prevents a legacy writer racing a guarded replacement.
	if j.Guarded || current.Guarded {
		if !remoteupdate.JobIdentityValid(jobIdentity(j)) {
			return fmt.Errorf("upgrade owner malformed")
		}
		if readErr == nil && !remoteupdate.JobWriteAllowed(jobIdentity(current), jobIdentity(j), expectedOwner != nil) {
			return fmt.Errorf("stale upgrade identity or transition rejected")
		}
	}
	if readErr == nil && current.ID != j.ID && (j.Guarded || current.Guarded) {
		historyPath := filepath.Join(root, "job-history-"+current.ID+".json")
		var history UpdateJob
		if err = readRemote(historyPath, &history); err == nil {
			if history != current {
				return fmt.Errorf("immutable upgrade history changed")
			}
		} else if !os.IsNotExist(err) {
			return err
		} else if err = writeRemote(historyPath, current); err != nil {
			return err
		}
	}
	if j.Guarded {
		j.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return writeRemote(filepath.Join(root, "job.json"), j)
}
func persistUpdateJob(root string, j UpdateJob) error { return writeJobOwned(root, j, nil, false) }

// Transfer is restricted to the verified old executable's worker, before its
// startup ack. Other writers never inherit ownership merely by knowing an ID.
func adoptUpgradeWorker(root string, j *UpdateJob) error {
	expected := jobIdentity(*j)
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(self, j.Old) || Verify(self) != nil {
		return fmt.Errorf("worker owner executable changed")
	}
	j.OwnerPID = uint32(os.Getpid())
	j.OwnerExecutable = self
	j.OwnerCreation, err = processCreation(j.OwnerPID)
	if err != nil {
		return err
	}
	return writeJobOwned(root, *j, &expected, false)
}

// Startup timeout stops only this exact recorded candidate's own graceful UI
// control. It cannot signal a later process or a different running instance.
func requestRecordedCandidateStop(j UpdateJob) *UpgradeStop {
	report := &UpgradeStop{processes: map[uint32]windows.Handle{}}
	h, err := ownedProcess(j.CandidatePID)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	defer windows.CloseHandle(h)
	var created, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exit, &kernel, &user) != nil || uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) != j.CandidateCreation {
		report.Error = "candidate creation identity changed"
		return report
	}
	var path [32768]uint16
	n := uint32(len(path))
	if windows.QueryFullProcessImageName(h, 0, &path[0], &n) != nil || !strings.EqualFold(windows.UTF16ToString(path[:n]), j.CandidateExecutable) {
		report.Error = "candidate executable identity changed"
		return report
	}
	callback := windows.NewCallback(func(hwnd, param uintptr) uintptr {
		if windowPID(hwnd) != j.CandidatePID || windowText(hwnd, true) != "SuhangUSBStatus061" {
			return 1
		}
		state, err := windows.WaitForSingleObject(h, 0)
		if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
			return 1
		}
		button, _, _ := upgradeUI.NewProc("GetDlgItem").Call(hwnd, 101)
		if button == 0 || !strings.EqualFold(windowText(button, true), "Button") || windowPID(hwnd) != j.CandidatePID {
			report.Error = "candidate graceful stop control unavailable"
			return 1
		}
		var result uintptr
		ok, _, _ := upgradeUI.NewProc("SendMessageTimeoutW").Call(hwnd, 0x111, 101, button, 0x2, 2000, uintptr(unsafe.Pointer(&result)))
		if ok == 0 {
			report.Error = "candidate graceful stop request timed out"
		} else {
			report.Requested++
		}
		return 1
	})
	upgradeUI.NewProc("EnumWindows").Call(callback, 0)
	return report
}

// Recovery changes only the interrupted marker; receipts, signed bytes and
// recorded owner remain intact. It is never a normal owner write.
func interruptDeadUpgradeJob(root string, j UpdateJob, detail string) error {
	expected := jobIdentity(j)
	j.Status, j.Detail = "interrupted", detail
	return writeJobOwned(root, j, &expected, true)
}
