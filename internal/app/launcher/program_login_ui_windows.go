//go:build windows && amd64

package launcher

import (
	"fmt"
	"golang.org/x/sys/windows"
)

// Called only for the already source/owner-authenticated core IPC peer.
func pinProgramLoginUI(owner programExitOwner) (*programLoginUI, error) {
	if !owner.valid() {
		return nil, fmt.Errorf("CORE_UI_IDENTITY_INVALID")
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, owner.PID)
	if err != nil {
		return nil, err
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil || uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) != owner.Creation {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("CORE_UI_LIFETIME_CHANGED")
	}
	return &programLoginUI{close: func() { _ = windows.CloseHandle(h) }, exited: func() (bool, bool) {
		state, err := windows.WaitForSingleObject(h, 0)
		return state == windows.WAIT_OBJECT_0, err == nil && (state == windows.WAIT_OBJECT_0 || state == uint32(windows.WAIT_TIMEOUT))
	}}, nil
}
