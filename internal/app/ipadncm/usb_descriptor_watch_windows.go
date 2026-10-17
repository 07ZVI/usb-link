//go:build windows && amd64

package ipadncm

import (
	"context"
	"suhang/usbnet/internal/security/deviceguard"
	"time"
)

// Only the established application session calls this watcher. Own mode and
// grouping transitions finish before subscription. No packet/frame handler or
// periodic ticker can reach this descriptor read; a global event requests an
// actual same-target recheck instead of itself proving a device replacement.
func watchUSBDescriptorAttachment(ctx context.Context, before Snapshot, refuse func()) (func(), string) {
	return watchUSBDescriptorAttachmentWithProof(ctx, before, refuse, nil)
}
func watchUSBDescriptorAttachmentWithProof(ctx context.Context, before Snapshot, refuse func(), proof func(Snapshot) bool) (func(), string) {
	baseline := networkOnlyUSBEligible(before)
	if proof != nil {
		baseline = proof(before)
	}
	if !baseline || refuse == nil {
		return nil, "USB_DESCRIPTOR_WATCH_BASELINE_UNCONFIRMED"
	}
	events, unsubscribe, err := deviceguard.SubscribeChanges()
	if err != nil {
		return nil, "USB_DESCRIPTOR_WATCH_UNAVAILABLE"
	}
	// Subscribe before this fresh baseline to close the preparation/subscription
	// gap. An earlier descriptor or an unreadable current device cannot fill it.
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	started := time.Now()
	current := inventory(checkCtx)
	checkCancel()
	diagnostic := descriptorRecheckSummary("application_watch_baseline", before, current)
	diagnostic.QueryDurationMS = time.Since(started).Milliseconds()
	currentTarget := sameRootInstance(before, current)
	if proof != nil {
		currentTarget = proof(before) && proof(current)
	}
	diagnostic.SameRoot = currentTarget
	recordUSBDescriptorRecheck(diagnostic)
	if ctx.Err() != nil || !currentTarget || !HasActiveNCM(current) {
		unsubscribe()
		return nil, "USB_DESCRIPTOR_WATCH_CURRENT_TARGET_UNCONFIRMED"
	}
	watchCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer unsubscribe()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-events:
				checkCtx, cancel := context.WithTimeout(watchCtx, 5*time.Second)
				opDone := RecordConnectionOperation("usb_descriptor_event_recheck")
				started := time.Now()
				current := inventory(checkCtx)
				opDone()
				cancel()
				diagnostic := descriptorRecheckSummary("application_device_event", before, current)
				diagnostic.QueryDurationMS = time.Since(started).Milliseconds()
				if watchCtx.Err() != nil {
					return
				}
				currentTarget := sameRootInstance(before, current)
				if proof != nil {
					currentTarget = proof(before) && proof(current)
				}
				diagnostic.SameRoot = currentTarget
				recordUSBDescriptorRecheck(diagnostic)
				if !currentTarget || !HasActiveNCM(current) {
					refuse()
					return
				}
			}
		}
	}()
	return func() { stop(); <-done }, ""
}
