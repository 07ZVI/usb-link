//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"time"
)

// Complete native read after closing a held adapter, with no lifecycle writes.
func WaitResidentMacAdapterAbsentNative(ctx context.Context) error {
	if ctx == nil {
		return errors.New("USB_RESIDENT_MAC_ABSENCE_CONTEXT_REQUIRED")
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		absent, e := MacAdapterAbsentNative()
		if e != nil {
			return e
		}
		if absent {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("USB_RESIDENT_MAC_CLOSE_ABSENCE_UNCONFIRMED")
		case <-poll.C:
		}
	}
}
