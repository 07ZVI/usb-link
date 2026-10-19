//go:build windows && amd64

package ipadncm

import (
	"context"
	"strings"
	"suhang/usbnet/internal/security/deviceguard"
	"suhang/usbnet/internal/transport/ipadsession"
	"time"
)

func initialUSBConfigurationIdentity(s Snapshot) (initialUSBConfigurationTarget, bool) {
	if s.Error != "" || s.HubErrors != 0 || s.ConnectionReadErrors != 0 || len(s.ConnectionReadErrorCodes) != 0 || len(s.Devices) != 1 {
		return initialUSBConfigurationTarget{}, false
	}
	d := s.Devices[0]
	t := initialUSBConfigurationTarget{root: exactIPadRoot(s), hub: d.hub, port: d.port, pid: d.pid, bcd: d.usbBCDDevice, serial: d.usbSerial, product: d.USBProduct}
	return t, len(d.Errors) == 0 && d.PID == "12AB" && d.USBDescriptorIdentityVerified && d.usbIdentityPortStable && ipadsession.ValidUSBDescriptorIdentity(t.serial, t.product) && t.same(t)
}

func initialUSBConfigurationWaitTarget(s Snapshot) (initialUSBConfigurationTarget, bool) {
	t, ok := initialUSBConfigurationIdentity(s)
	return t, ok && s.Devices[0].CurrentConfiguration == 0 && networkUSBPreflight(s.Devices[0].Configurations, 3)
}

func waitInitialUSBConfiguration(ctx context.Context, initial Snapshot, inspect func() Snapshot) (Snapshot, bool, string) {
	target, applicable := initialUSBConfigurationWaitTarget(initial)
	if !applicable {
		return initial, false, ""
	}
	var notices <-chan struct{}
	if changes, unsubscribe, err := deviceguard.SubscribeChanges(); err == nil {
		notices = changes
		defer unsubscribe()
	}
	result := initial
	state := awaitInitialUSBConfiguration(ctx, notices, 2*time.Second, 250*time.Millisecond, func(cacheCtx context.Context) string {
		cfg := byte(0)
		state := "INITIAL_CONFIGURATION_TARGET_CHANGED_OR_UNREADABLE"
		if ready, _ := idleExactRootReadiness(cacheCtx, target.root); ready != "root_started_not_authorization" {
			return state
		}
		cached := inventoryProduct(cacheCtx, target.pid)
		if cacheCtx.Err() != nil || cached.Error != "" || cached.HubErrors != 0 || cached.ConnectionReadErrors != 0 || len(cached.ConnectionReadErrorCodes) != 0 || len(cached.Devices) != 1 {
			return state
		}
		d := cached.Devices[0]
		if !strings.EqualFold(d.hub, target.hub) || d.port != target.port || d.pid != target.pid || d.usbBCDDevice != target.bcd {
			return state
		}
		if ready, _ := idleExactRootReadiness(cacheCtx, target.root); ready != "root_started_not_authorization" {
			return state
		}
		cfg = d.CurrentConfiguration
		state = "INITIAL_CONFIGURATION_UNSUPPORTED"
		if cfg == 0 {
			state = "INITIAL_CONFIGURATION_ZERO"
		} else if (cfg == 3 || cfg == 5) && networkUSBPreflight(initial.Devices[0].Configurations, cfg) {
			state = "INITIAL_CONFIGURATION_CACHE_READY"
		}
		return state
	}, func() bool {
		if ctx.Err() != nil {
			return false
		}
		result = inspect()
		fresh, ok := initialUSBConfigurationIdentity(result)
		return ctx.Err() == nil && ok && target.same(fresh) && networkOnlyUSBEligible(result)
	})
	return result, true, state
}
