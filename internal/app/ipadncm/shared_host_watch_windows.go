//go:build windows && amd64

package ipadncm

import (
	"context"
	"sort"
	"strings"
	"suhang/usbnet/internal/app/startuptelemetry"
	"suhang/usbnet/internal/app/usbhost"
	"suhang/usbnet/internal/security/deviceguard"
	"time"
)

// Own subscription: never consume another device session's wake channel.
// Filter native cached Apple USB IDs so creating a Wintun adapter cannot
// recursively trigger rapid retries of its own failed preparation.
func WatchSharedHostDeviceChanges(ctx context.Context) func() {
	match := func(id string) bool {
		id = strings.ToUpper(id)
		return strings.HasPrefix(id, `USB\VID_05AC&PID_`) && !strings.Contains(id, "&MI_") && (strings.HasPrefix(id, `USB\VID_05AC&PID_1903\`) || strings.HasPrefix(id, `USB\VID_05AC&PID_12`))
	}
	events, unsubscribe, err := deviceguard.SubscribeFilteredChanges(match)
	interfaces, unsubscribeInterfaces, interfaceError := deviceguard.SubscribeUSBInterfaceChanges(match)
	RecordConnectionTimingNativeRegistration(err == nil || interfaceError == nil)
	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if unsubscribe != nil {
			defer unsubscribe()
		}
		if unsubscribeInterfaces != nil {
			defer unsubscribeInterfaces()
		}
		var fallback <-chan time.Time
		var tick *time.Ticker
		if err != nil || interfaceError != nil {
			tick = time.NewTicker(2 * time.Second)
			fallback = tick.C
			defer tick.Stop()
		}
		fingerprint := func() (string, bool) {
			ids, ok := idlePnPIDs(watchCtx)
			if !ok {
				return "", false
			}
			for device, selected := range map[string][]string{"Mac": onlyMacIDs(ids), "iPad": onlyIPadIDs(ids)} {
				_, presence := idleUSBPresenceFromIDs(selected, true)
				if startuptelemetry.ObserveDevicePresence(device, presence.identity, presence.readable && (presence.candidate || presence.absent), presence.absent) {
					signalStartupTiming()
				}
			}
			ids = append(onlyMacIDs(ids), onlyIPadIDs(ids)...)
			sort.Strings(ids)
			return strings.Join(ids, "\n"), true
		}
		last, valid := fingerprint()
		usbhost.NudgeSharedHost()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-events:
				archiveOwnerNotice("watcher_delivery", "device_instance_hint", 0)
				RecordConnectionTimingNativeNotice(0)
				// A native Apple root event triggers even when a fast same-root
				// unplug/replug coalesces to an unchanged present-device inventory.
				usbhost.NudgeSharedHost()
				// Session 0 has no UI window to receive WM_DEVICECHANGE. Wake
				// the core's own idle loop; it still performs fresh PnP inspection
				// before admitting a device. This is never a consent/ready signal.
				signalConnectionChanged(0)
			case <-interfaces:
				if !connectionTimingUSBInterfaceWakeEnabled() {
					continue
				}
				archiveOwnerNotice("watcher_delivery", "usb_interface_hint", 1)
				RecordConnectionTimingNativeNotice(1)
				usbhost.NudgeSharedHost()
				signalConnectionChanged(0)
			case <-fallback:
			}
			current, ok := fingerprint()
			if ok && (!valid || current != last) {
				usbhost.NudgeSharedHost()
				signalConnectionChanged(0)
			}
			if ok {
				last, valid = current, true
			}
		}
	}()
	return func() { cancel(); <-done }
}
