//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"strings"
	"time"
	"unsafe"
)

// Uses the existing graceful Stop button in verified prior executables. It never
// terminates a process, executes a downloaded binary, or sends a generic close.
type UpgradeStop struct {
	Requested                    int    `json:"graceful_stop_requests"`
	Error                        string `json:"error,omitempty"`
	processes                    map[uint32]windows.Handle
	active                       map[uint32]bool
	scanCallback, finishCallback uintptr
}

var upgradeUI = windows.NewLazySystemDLL("user32.dll")

func windowText(hwnd uintptr, class bool) string {
	var buf [4096]uint16
	method := "GetWindowTextW"
	if class {
		method = "GetClassNameW"
	}
	n, _, _ := upgradeUI.NewProc(method).Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf[:min(int(n), len(buf))])
}
func windowPID(hwnd uintptr) uint32 {
	var pid uint32
	upgradeUI.NewProc("GetWindowThreadProcessId").Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	return pid
}
func ownedProcess(pid uint32) (windows.Handle, error) {
	if pid == uint32(os.Getpid()) {
		return 0, fmt.Errorf("current process")
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return 0, e
	}
	var buf [32768]uint16
	size := uint32(len(buf))
	if e = windows.QueryFullProcessImageName(h, 0, &buf[0], &size); e != nil {
		windows.CloseHandle(h)
		return 0, e
	}
	path := windows.UTF16ToString(buf[:size])
	if Verify(path) == nil {
		return h, nil
	}
	sum, e := fileHash(path)
	if e == nil {
		if knownUpgradeExecutable[sum] {
			return h, nil
		}
		if current, err := os.Executable(); err == nil {
			if self, err := fileHash(current); err == nil && self == sum {
				return h, nil
			}
		}
	}
	windows.CloseHandle(h)
	return 0, fmt.Errorf("previous process executable not verified")
}
func RequestPreviousStop() *UpgradeStop {
	report := &UpgradeStop{processes: map[uint32]windows.Handle{}}
	if binding, present, err := readCoreBinding(); err != nil {
		report.Error = err.Error()
		return report
	} else if present {
		pid, err := coreProcess(binding.Executable)
		if err == nil {
			if handle, e := ownedProcess(pid); e == nil {
				report.processes[pid] = handle
			} else {
				report.Error = e.Error()
				return report
			}
		}
		if err = StopCoreService(); err != nil {
			report.Error = err.Error()
			return report
		}
		if len(report.processes) > 0 {
			report.Requested++
		}
	}

	callback := windows.NewCallback(func(hwnd, param uintptr) uintptr {
		if windowText(hwnd, true) != "SuhangUSBStatus061" {
			return 1
		}
		pid := windowPID(hwnd)
		if pid == uint32(os.Getpid()) {
			return 1
		}
		h, e := ownedProcess(pid)
		if e != nil {
			report.Error = e.Error()
			return 1
		}
		stop, _, _ := upgradeUI.NewProc("GetDlgItem").Call(hwnd, 101)
		if stop == 0 || !strings.EqualFold(windowText(stop, true), "Button") {
			windows.CloseHandle(h)
			report.Error = "previous stop control unavailable"
			return 1
		}
		if windowPID(hwnd) != pid {
			windows.CloseHandle(h)
			return 1
		}
		var result uintptr
		ok, _, _ := upgradeUI.NewProc("SendMessageTimeoutW").Call(hwnd, 0x111, 101, stop, 0x2, 2000, uintptr(unsafe.Pointer(&result)))
		if ok == 0 {
			windows.CloseHandle(h)
			report.Error = "previous graceful stop request timed out"
			return 1
		}
		report.Requested++
		report.processes[pid] = h
		return 1
	})
	upgradeUI.NewProc("EnumWindows").Call(callback, 0)
	return report
}
func (r *UpgradeStop) Close() {
	for _, h := range r.processes {
		windows.CloseHandle(h)
	}
	r.processes = nil
}

// Older releases hold launch.lock while showing their final diagnostic message.
// Acknowledge only that completion message after their status window has gone.
func (r *UpgradeStop) AcknowledgeCompleted() {
	r.active = map[uint32]bool{}
	if r.scanCallback == 0 {
		r.scanCallback = windows.NewCallback(func(hwnd, param uintptr) uintptr {
			if windowText(hwnd, true) == "SuhangUSBStatus061" {
				r.active[windowPID(hwnd)] = true
			}
			return 1
		})
	}
	upgradeUI.NewProc("EnumWindows").Call(r.scanCallback, 0)
	if r.finishCallback == 0 {
		r.finishCallback = windows.NewCallback(func(hwnd, param uintptr) uintptr {
			pid := windowPID(hwnd)
			h, ok := r.processes[pid]
			if !ok || r.active[pid] || windowText(hwnd, true) != "#32770" || windowText(hwnd, false) != "隨航 USB — Mac / iPad" {
				return 1
			}
			if state, _ := windows.WaitForSingleObject(h, 0); state != uint32(windows.WAIT_TIMEOUT) {
				return 1
			}
			text, _, _ := upgradeUI.NewProc("GetDlgItem").Call(hwnd, 0xffff)
			// Standard MessageBox text control is 0xFFFF. No button is pressed unless
			// the completion message explicitly includes the saved diagnostic archive.
			var contentBuffer [4096]uint16
			var length uintptr
			read, _, _ := upgradeUI.NewProc("SendMessageTimeoutW").Call(text, 0xD, uintptr(len(contentBuffer)), uintptr(unsafe.Pointer(&contentBuffer[0])), 0x2, 1000, uintptr(unsafe.Pointer(&length)))
			if read == 0 {
				return 1
			}
			content := windows.UTF16ToString(contentBuffer[:min(int(length), len(contentBuffer))])
			if !strings.Contains(content, "USB連線診斷資料.zip") {
				return 1
			}
			done, _, _ := upgradeUI.NewProc("GetDlgItem").Call(hwnd, 1)
			if done != 0 {
				upgradeUI.NewProc("PostMessageW").Call(hwnd, 0x111, 1, done)
			}
			return 1
		})
	}
	upgradeUI.NewProc("EnumWindows").Call(r.finishCallback, 0)
}

func (r *UpgradeStop) WaitForCleanup(open func() (string, windows.Handle, string)) (string, windows.Handle, string) {
	deadline := time.Now().Add(90 * time.Second)
	for {
		dir, lock, reason := open()
		if reason != "ANOTHER_LAUNCH_OR_RECOVERY_LOCK_UNAVAILABLE" || r.Requested == 0 || time.Now().After(deadline) {
			return dir, lock, reason
		}
		r.AcknowledgeCompleted()
		time.Sleep(250 * time.Millisecond)
	}
}
