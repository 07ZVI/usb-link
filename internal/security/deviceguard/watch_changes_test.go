package deviceguard

import (
	"context"
	"suhang/usbnet/internal/security/securitypolicy"
	"sync/atomic"
	"testing"
	"time"
)

func TestChangesIdleDoesNotPollAndEventStopsUnexpectedHID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	events := make(chan struct{}, 1)
	reports := make(chan struct{}, 4)
	done := make(chan struct{})
	var calls atomic.Int32
	var stopped atomic.Bool
	go func() {
		defer close(done)
		WatchChanges(ctx, "root", events, time.Millisecond, func(context.Context, string) securitypolicy.DeviceVerdict {
			n := calls.Add(1)
			if n == 1 {
				return securitypolicy.DeviceVerdict{Admit: true}
			}
			return securitypolicy.DeviceVerdict{Code: "USB_UNEXPECTED_HID_INTERFACE"}
		}, func(securitypolicy.DeviceVerdict) { reports <- struct{}{} }, func() { stopped.Store(true) })
	}()
	select {
	case <-reports:
	case <-ctx.Done():
		t.Fatal("initial admission missing")
	}
	select {
	case <-reports:
		t.Fatal("idle polled")
	case <-time.After(15 * time.Millisecond):
	}
	events <- struct{}{}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("event not handled")
	}
	if !stopped.Load() || calls.Load() != 2 {
		t.Fatal(calls.Load(), stopped.Load())
	}
}
func TestChangesUnknownInventoryRetriesAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	events := make(chan struct{}, 1)
	n := 0
	stopped := false
	WatchChanges(ctx, "root", events, time.Millisecond, func(context.Context, string) securitypolicy.DeviceVerdict {
		n++
		return securitypolicy.DeviceVerdict{Code: "USB_SECURITY_INVENTORY_UNAVAILABLE"}
	}, nil, func() { stopped = true })
	if n != 3 || !stopped {
		t.Fatal(n, stopped)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	stopped = false
	WatchChanges(ctx2, "root", events, time.Second, func(context.Context, string) securitypolicy.DeviceVerdict {
		return securitypolicy.DeviceVerdict{Admit: true}
	}, nil, func() { stopped = true })
	if stopped {
		t.Fatal("normal cancellation classified as security failure")
	}
}
