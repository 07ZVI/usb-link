package deviceguard

import (
	"context"
	"suhang/usbnet/internal/security/securitypolicy"
	"time"
)

type USBObserver func(context.Context, string) securitypolicy.DeviceVerdict

// Watch is advisory for the OS input path and enforcing for our USB network.
// It never reads keystrokes, disables devices or polls on the packet fast path.
// Root disappearance may be our own configuration transition; existing
// transport ownership checks decide detachment. Unreadable inventories are
// reported immediately and stop the session after three consecutive samples.
func Watch(ctx context.Context, root string, period time.Duration, observe USBObserver, report func(securitypolicy.DeviceVerdict), stop func()) {
	if period <= 0 || observe == nil || stop == nil {
		return
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	unknown := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v := observe(ctx, root)
			if ctx.Err() != nil {
				return
			}
			if report != nil {
				report(v)
			}
			if v.Admit || v.Code == "USB_SECURITY_ROOT_ABSENT" {
				unknown = 0
				continue
			}
			if v.Code == "USB_UNEXPECTED_HID_INTERFACE" {
				stop()
				return
			}
			unknown++
			if unknown >= 3 {
				stop()
				return
			}
		}
	}
}
