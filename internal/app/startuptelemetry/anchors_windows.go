//go:build windows && amd64

package startuptelemetry

import (
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsDLL     = windows.NewLazySystemDLL("wtsapi32.dll")
	wtsQuery   = wtsDLL.NewProc("WTSQuerySessionInformationW")
	wtsFree    = wtsDLL.NewProc("WTSFreeMemory")
	copyNative = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory")
	getUptime  = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")
)

// SDK WTSINFOW has 32+17+21 WCHAR arrays between its fixed header and
// LARGE_INTEGER times. Their contents are deliberately never copied or read.
type wtsInfoSDK struct {
	State, SessionID, IncomingBytes, OutgoingBytes, IncomingFrames, OutgoingFrames, IncomingCompressedBytes, OutgoingCompressedBytes uint32
	WinStation                                                                                                                       [32]uint16
	Domain                                                                                                                           [17]uint16
	UserName                                                                                                                         [21]uint16
	Connect, Disconnect, LastInput, Logon, Current                                                                                   int64
}

func captureNativeAnchors() Anchors {
	now := time.Now().UTC()
	a := Anchors{CapturedAt: now, Boot: Anchor{Source: "GET_TICK_COUNT64_WALL_TIME_ESTIMATE_INCLUDES_SLEEP_FAST_STARTUP", Problem: "BOOT_UPTIME_UNAVAILABLE"}, Logon: Anchor{Source: "WTS_CURRENT_PROCESS_SESSION_LOGON_TIME", Problem: "INTERACTIVE_LOGON_UNAVAILABLE"}, Process: Anchor{Source: "GET_PROCESS_TIMES_CREATION", Problem: "PROCESS_CREATION_UNAVAILABLE"}}
	var creation, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user) == nil {
		if at, ok := filetimeAnchor(uint64(creation.HighDateTime)<<32|uint64(creation.LowDateTime), now); ok {
			a.Process = Anchor{Available: true, At: &at, Source: a.Process.Source}
		}
	}
	if getUptime.Find() == nil {
		ms, _, _ := getUptime.Call()
		// Bound arithmetic to avoid overflowing time.Duration on bad native data.
		if ms > 0 && uint64(ms) < uint64((3650*24*time.Hour)/time.Millisecond) {
			at := time.Now().UTC().Add(-time.Duration(ms) * time.Millisecond)
			a.Boot = Anchor{Available: true, At: &at, Source: a.Boot.Source}
		}
	}
	var session uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) != nil || session == 0 || wtsQuery.Find() != nil || wtsFree.Find() != nil || copyNative.Find() != nil {
		return a
	}
	var buffer uintptr
	var size uint32
	ok, _, _ := wtsQuery.Call(0, uintptr(session), 24, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&size))) // WTSSessionInfo=24, current local server
	if buffer != 0 {
		defer wtsFree.Call(buffer)
	}
	if ok == 0 || buffer == 0 || size < uint32(unsafe.Sizeof(wtsInfoSDK{})) || size > 4096 {
		return a
	}
	var header struct{ State, SessionID uint32 }
	copyNative.Call(uintptr(unsafe.Pointer(&header)), buffer, unsafe.Sizeof(header))
	var times struct{ Logon, Current int64 }
	copyNative.Call(uintptr(unsafe.Pointer(&times)), buffer+unsafe.Offsetof(wtsInfoSDK{}.Logon), unsafe.Sizeof(times))
	runtime.KeepAlive(header)
	runtime.KeepAlive(times)
	if header.SessionID != session || (header.State != 0 && header.State != 1 && header.State != 4) || times.Logon <= 0 || times.Current < times.Logon {
		return a
	}
	queryNow := time.Now().UTC()
	current, valid := filetimeAnchor(uint64(times.Current), queryNow)
	if !valid || queryNow.Sub(current) > 30*time.Second {
		return a
	}
	at, valid := filetimeAnchor(uint64(times.Logon), queryNow)
	if !valid || (a.Process.Available && a.Process.At != nil && at.After(a.Process.At.Add(time.Second))) {
		return a
	}
	a.Logon = Anchor{Available: true, At: &at, Source: a.Logon.Source}
	return a
}
