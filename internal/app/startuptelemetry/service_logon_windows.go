//go:build windows && amd64

package startuptelemetry

import (
	"runtime"
	"time"
	"unsafe"

)

// ObserveAuthenticatedSession must be called only for the owner's session
// freshly verified by the local service IPC. It reads WTSSessionInfo rather
// than WTSLogonTime (which is unsupported) and never subtracts host clocks.
func ObserveAuthenticatedSession(session uint32) bool {
	if session == 0 || session == 0xffffffff || wtsQuery.Find() != nil || wtsFree.Find() != nil || copyNative.Find() != nil {
		return false
	}
	var buffer uintptr
	var size uint32
	result, _, _ := wtsQuery.Call(0, uintptr(session), 24, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&size)))
	if buffer != 0 {
		defer wtsFree.Call(buffer)
	}
	if result == 0 || buffer == 0 || size < uint32(unsafe.Sizeof(wtsInfoSDK{})) || size > 4096 {
		return false
	}
	var header struct{ State, SessionID uint32 }
	var times struct{ Logon, Current int64 }
	copyNative.Call(uintptr(unsafe.Pointer(&header)), buffer, unsafe.Sizeof(header))
	copyNative.Call(uintptr(unsafe.Pointer(&times)), buffer+unsafe.Offsetof(wtsInfoSDK{}.Logon), unsafe.Sizeof(times))
	runtime.KeepAlive(header)
	runtime.KeepAlive(times)
	if header.SessionID != session || header.State != 0 || times.Logon <= 0 || times.Current < times.Logon {
		return false
	}
	now := time.Now().UTC()
	current, ok := filetimeAnchor(uint64(times.Current), now)
	if !ok || now.Sub(current) > 30*time.Second {
		return false
	}
	logon, ok := filetimeAnchor(uint64(times.Logon), now)
	if !ok {
		return false
	}
	Init()
	return global.tracker.ObserveLogon(Anchor{Available: true, At: &logon, Source: "WTS_AUTHENTICATED_OWNER_SESSION_LOGON_TIME"})
}
