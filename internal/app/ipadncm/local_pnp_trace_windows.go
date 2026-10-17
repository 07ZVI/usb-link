//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"sync"

	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/security/deviceguard"
)

var localPnPTrace = newLocalPnPTraceController()
var localPnPTraceOnce sync.Once

func StartLocalPnPTrace(ctx context.Context) func() {
	stop := func() {}
	if buildinfo.LocalDiagnostics != "true" {
		return stop
	}
	localPnPTraceOnce.Do(func() {
		localPnPTrace.open = func() (localPnPSource, func(), error) { return deviceguard.SubscribeAppleChangeMetadata() }
		localPnPTrace.archive = RecordConnectionArchiveEventAccepted
		run, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go localPnPTrace.run(run, done)
		stop = func() { cancel(); <-done }
	})
	return stop
}

func SetLocalPnPTraceMaster(on bool) {
	localPnPTrace.master(on && buildinfo.LocalDiagnostics == "true")
}
func LocalPnPTraceDiagnostics() any { return localPnPTrace.snapshot() }
