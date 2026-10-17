//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"strings"
	"suhang/usbnet/internal/buildinfo"
	"sync"
	"time"
)

var localWPDTrace = newAutomaticLocalWPDTraceController()
var localWPDTraceStart sync.Once

func StartLocalWPDTrace(ctx context.Context, dir string) func() {
	var stop func()
	localWPDTraceStart.Do(func() {
		run, cancel := context.WithCancel(ctx)
		localWPDTrace.mu.Lock()
		localWPDTrace.ctx = run
		localWPDTrace.mu.Unlock()
		localWPDTrace.stamp = func() (string, string, int64) {
			now := time.Now()
			id, ms := trustDiagnostics.stamp(now)
			return now.UTC().Format(time.RFC3339Nano), id, ms
		}
		localWPDTrace.backend = &localWPDTraceNative{dir: dir, stamp: func() int64 { _, ms := trustDiagnostics.stamp(time.Now()); return ms }}
		done := make(chan struct{})
		go localWPDTrace.run(run, done)
		stop = func() { cancel(); <-done }
	})
	if stop == nil {
		return func() {}
	}
	return stop
}
func SetLocalWPDTracePersistence(save func(bool) error, read func() (bool, error)) {
	localWPDTrace.configure(save, read)
}

// This is deliberately memory-only; developer control invokes it under its
// revision lock. Preference I/O and stopping ETW run on independent workers.
func SetLocalWPDTraceMaster(on bool) {
	localWPDTrace.masterChanged(on && buildinfo.LocalDiagnostics == "true")
}
func SetLocalWPDTrace(on bool, id string) error {
	if on && buildinfo.LocalDiagnostics != "true" {
		if len(id) == 32 && strings.Trim(id, "0123456789abcdefABCDEF") == "" {
			localWPDTrace.mu.Lock()
			localWPDTrace.state.RejectedID = id
			localWPDTrace.state.RejectedError = "WPD_TRACE_LOCAL_DIAGNOSTICS_REQUIRED"
			localWPDTrace.mu.Unlock()
		}
		return errors.New("WPD_TRACE_LOCAL_DIAGNOSTICS_REQUIRED")
	}
	return localWPDTrace.set(on, id)
}
func LocalWPDTraceDiagnostics() any { return localWPDTrace.snapshot() }
