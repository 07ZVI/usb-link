//go:build windows && amd64 && !usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"sync"
)

var localWPDTracePublic struct {
	sync.Mutex
	err error
}

func StartLocalWPDTrace(_ context.Context, dir string) func() {
	e := RestoreLocalWPDTrace(dir)
	localWPDTracePublic.Lock()
	localWPDTracePublic.err = e
	localWPDTracePublic.Unlock()
	return func() {}
}
func SetLocalWPDTracePersistence(func(bool) error, func() (bool, error)) {}
func SetLocalWPDTraceMaster(bool)                                        {}
func SetLocalWPDTrace(on bool, _ string) error {
	if on {
		return errors.New("WPD_TRACE_LOCAL_BUILD_REQUIRED")
	}
	return nil
}
func LocalWPDTraceDiagnostics() any {
	localWPDTracePublic.Lock()
	defer localWPDTracePublic.Unlock()
	if localWPDTracePublic.err != nil {
		return map[string]any{"available": false, "phase": "recovery_pending", "error": "WPD_TRACE_RESTORE_FAILED"}
	}
	return nil
}
