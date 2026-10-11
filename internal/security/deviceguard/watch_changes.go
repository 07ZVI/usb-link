package deviceguard

import (
	"context"
	"suhang/usbnet/internal/security/securitypolicy"
	"sync/atomic"
	"time"
)

var pollingBaseline atomic.Bool

func PollingBaseline() bool { return pollingBaseline.Load() }

// Unknown inventories keep the old retry cadence and three-sample stop policy.
func WatchChanges(ctx context.Context, root string, events <-chan struct{}, retry time.Duration, observe USBObserver, report func(securitypolicy.DeviceVerdict), stop func()) {
	if events == nil || retry <= 0 || observe == nil || stop == nil {
		return
	}
	unknown := 0
	var timer *time.Timer
	var retryC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	check := func() bool {
		v := observe(ctx, root)
		if ctx.Err() != nil {
			return false
		}
		if report != nil {
			report(v)
		}
		if v.Admit || v.Code == "USB_SECURITY_ROOT_ABSENT" {
			unknown = 0
			if timer != nil {
				timer.Stop()
			}
			retryC = nil
			if pollingBaseline.Load() {
				timer = time.NewTimer(retry)
				retryC = timer.C
			}
			return true
		}
		if v.Code == "USB_UNEXPECTED_HID_INTERFACE" {
			stop()
			return false
		}
		unknown++
		if unknown >= 3 {
			stop()
			return false
		}
		if timer != nil {
			timer.Stop()
		}
		timer = time.NewTimer(retry)
		retryC = timer.C
		return true
	}
	if !check() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				stop()
				return
			}
			if retryC != nil && unknown > 0 {
				continue
			}
			if !check() {
				return
			}
		case <-retryC:
			retryC = nil
			if !check() {
				return
			}
		}
	}
}
