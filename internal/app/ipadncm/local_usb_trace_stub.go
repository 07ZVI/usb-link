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
	s := newUSBTraceStatus()
	s.QueryOwnership, s.FirstQueryFailure = usbTraceQuerySnapshot()
	s.Available = false
	s.Phase = "local_build_required"
	usbTraceStub.Lock()
	failed := usbTraceStub.recoveryFailed
	usbTraceStub.Unlock()
	if failed {
		s.Phase = "recovery_pending"
		s.RecoveryPending = true
		s.Coverage = "incomplete"
		s.Error = "USB_TRACE_RECOVERY_FAILED"
	}
	return s
}
