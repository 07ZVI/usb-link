//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"strings"
	"time"
)

// WaitOwnedMacCloseAbsentNative only observes a just-closed actual creator.
// Its caller must capture this exact instance/index/LUID while holding that
// creator and its protected live session, before invoking Close. This API does
// not delete/adopt an adapter, restore configuration or authorize journal use.
func WaitOwnedMacCloseAbsentNative(ctx context.Context, index uint32, luid uint64, instance string) error {
	if ctx == nil || index == 0 || luid == 0 || instance == "" || len(instance) > 1024 || strings.ContainsAny(instance, "*?\x00") {
		return errors.New("USB_MAC_LIFETIME_CLOSE_SCOPE_UNPROVEN")
	}
	// Use the real old LUID for address absence. A removed interface's numeric
	// index may be reused by another interface; no address is deleted here.
	observe := func() (bool, error) {
		absent, err := nativeWintunRemovalAbsent(instance, NativeMacGUID, "USB Link")
		if err != nil || !absent {
			return absent, err
		}
		if err := nativeHostIPv4Absent(nativeHostInterface{LUID: luid}); err != nil {
			if err.Error() == "USB_HOST_IPV4_REMAINS_BEFORE_ADAPTER_REMOVAL" {
				return false, nil // readable remaining row is pending, not absence.
			}
			return false, err
		}
		return true, nil
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	return waitWintunCloseSettle(ctx, observe, deadline.C, poll.C)
}
