//go:build windows && amd64

package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"
)

// WaitOwnedMacCloseAbsentNative only observes a just-closed actual creator.
// Its caller must capture this exact instance/index/LUID while holding that
// creator and its protected live session, before invoking Close. This API does
// not delete/adopt an adapter, restore configuration or authorize journal use.
func WaitOwnedMacCloseAbsentNative(ctx context.Context, index uint32, luid uint64, instance string, logger *log.Logger) (err error) {
	if ctx == nil || !wintunCloseScopeValid(index, luid, instance) {
		return errors.New("USB_MAC_LIFETIME_CLOSE_SCOPE_UNPROVEN")
	}
	start := time.Now()
	var last wintunCloseObservation
	var observations uint32
	var parentRecoveryRequired bool
	defer func() {
		if logger != nil {
			row := struct {
				wintunCloseObservation
				Observations           uint32 `json:"observations"`
				ElapsedMS              int64  `json:"elapsed_ms"`
				Confirmed              bool   `json:"confirmed"`
				ParentRecoveryRequired bool   `json:"parent_recovery_required"`
			}{last, observations, time.Since(start).Milliseconds(), err == nil, parentRecoveryRequired}
			if data, e := json.Marshal(row); e == nil {
				logger.Printf("USB_MAC_NORMAL_CLOSE %s", data)
			}
		}
	}()
	// This is live creator closure, not a DIF_REMOVE transaction. Nonpresent
	// installation records remain outside its proof and grant no new authority.
	observe := func() (bool, error) {
		var readErr error
		last, readErr = observeOwnedMacCloseNative(luid, instance)
		observations++
		absent, handoff, decisionErr := last.closeResult(readErr)
		parentRecoveryRequired = handoff
		return absent, decisionErr
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	return waitWintunCloseSettle(ctx, observe, deadline.C, poll.C)
}
