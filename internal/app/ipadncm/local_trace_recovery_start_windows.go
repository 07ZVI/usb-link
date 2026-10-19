//go:build windows && amd64

package ipadncm

import (
	"context"
	"log"
)

// The WPD and USB ETW traces existed only in developer builds that are no
// longer part of this tree. A developer build may have left an ETW session
// running; these starters stop it once at startup. A failure is logged and the
// next start retries because the journal is kept until the stop is confirmed.
func StartLocalWPDTrace(_ context.Context, dir string) func() {
	if err := RestoreLocalWPDTrace(dir); err != nil {
		log.Printf("WPD_TRACE_RESTORE_FAILED: %v", err)
	}
	return func() {}
}

func StartLocalUSBTrace(_ context.Context, dir string) func() {
	if err := RestoreLocalUSBTrace(dir); err != nil {
		log.Printf("USB_TRACE_RESTORE_FAILED: %v", err)
	}
	return func() {}
}
