package deviceguard

import (
	"context"
	"suhang/usbnet/internal/security/securitypolicy"
	"testing"
	"time"
)

func TestWatchStopsUnexpectedInputWithoutWaitingForManualReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stopped := false
	Watch(ctx, "root", time.Millisecond, func(context.Context, string) securitypolicy.DeviceVerdict {
		return securitypolicy.DeviceVerdict{Code: "USB_UNEXPECTED_HID_INTERFACE"}
	}, nil, func() { stopped = true })
	if !stopped {
		t.Fatal("unexpected input did not stop network")
	}
}

func TestWatchDoesNotTreatModeChangeAbsenceAsAttackAndFailsRepeatedUnknown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	stopped := false
	Watch(ctx, "root", time.Millisecond, func(context.Context, string) securitypolicy.DeviceVerdict {
		calls++
		if calls <= 4 {
			return securitypolicy.DeviceVerdict{Code: "USB_SECURITY_ROOT_ABSENT"}
		}
		return securitypolicy.DeviceVerdict{Code: "USB_SECURITY_INVENTORY_UNAVAILABLE"}
	}, nil, func() { stopped = true })
	if !stopped || calls != 7 {
		t.Fatal(stopped, calls)
	}
}
