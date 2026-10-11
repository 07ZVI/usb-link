//go:build windows && amd64

package macconnection

import (
	"golang.org/x/sys/windows"
	"strings"
)

// Parent holds Go's actual child process handle until Wait. Querying this exact
// just-launched PID cannot become an arbitrary process control endpoint.
func captureNativeFailureChild(pid uint32, source, nonce string) (nativeChildBinding, bool) {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return nativeChildBinding{}, false
	}
	defer windows.CloseHandle(h)
	actual, e := windows.GetProcessId(h)
	if e != nil || actual != pid {
		return nativeChildBinding{}, false
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return nativeChildBinding{}, false
	}
	path := make([]uint16, 32768)
	size := uint32(len(path))
	if windows.QueryFullProcessImageName(h, 0, &path[0], &size) != nil || size == 0 || size >= uint32(len(path)) || !strings.EqualFold(windows.UTF16ToString(path[:size]), source) {
		return nativeChildBinding{}, false
	}
	creation := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if creation == 0 {
		return nativeChildBinding{}, false
	}
	return nativeChildBinding{pid: pid, creation: creation, nonce: nonce}, true
}
