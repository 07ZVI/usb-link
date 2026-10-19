//go:build !windows || !amd64 || !usblink_local_remote

package ipadncm

import (
	"context"
	"sync"
)

var usbTraceStub struct {
	sync.Mutex
	recoveryFailed bool
}

func StartLocalUSBTrace(_ context.Context, dir string) func() {
	e := RestoreLocalUSBTrace(dir)
	usbTraceStub.Lock()
	usbTraceStub.recoveryFailed = e != nil
	usbTraceStub.Unlock()
	return func() {}
}
func SetLocalUSBTraceMaster(bool) {}
func LocalUSBTraceDiagnostics() any {
	last, first := usbTraceQuerySnapshot()
	s := map[string]any{"available": false, "requested": false, "active": false, "phase": "local_build_required",
		"query_ownership": last, "first_query_failure": first}
	usbTraceStub.Lock()
	failed := usbTraceStub.recoveryFailed
	usbTraceStub.Unlock()
	if failed {
		s["phase"] = "recovery_pending"
		s["recovery_pending"] = true
		s["coverage"] = "incomplete"
		s["error"] = "USB_TRACE_RECOVERY_FAILED"
	}
	return s
}
