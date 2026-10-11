//go:build windows && amd64

package ipadncm

import (
	"context"
	"golang.org/x/sys/windows"
	"sync/atomic"
	"time"
)

var lastAttemptIdentity atomic.Value
var sameAttachmentRetry atomic.Bool
var automaticRetries autoRetryBudget

func ConsumeSameAttachmentRetry() bool { return sameAttachmentRetry.Swap(false) }

var connectionChanged = make(chan struct{}, 1)
var connectionRetry = make(chan struct{}, 1)

func signalConnectionChanged(code uint32) {
	monitorDiagnostics.notice(code)
	select {
	case connectionChanged <- struct{}{}:
	default:
	}
}
func requestConnectionRetry() {
	s := connectionMonitor()
	if s == nil || (s.snapshot().Status != "MONITOR_PAUSED" && s.snapshot().Status != "MONITOR_RETRYING") || connectionContext().Err() != nil {
		return
	}
	select {
	case connectionRetry <- struct{}{}:
		recordManualRetry()
	default:
	}
}

// This idle path reads Windows' present-device cache only. It never opens a
// hub, reads descriptors, contacts Apple services or starts a mode/network trial.
func idlePnPIDs(ctx context.Context) ([]string, bool) {
	set, e := windows.SetupDiGetClassDevsEx(nil, "USB", 0, windows.DIGCF_PRESENT|windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		return nil, false
	}
	defer set.Close()
	var ids []string
	for i := 0; i < 4096 && ctx.Err() == nil; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			return ids, true
		}
		if e != nil {
			return nil, false
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			return nil, false
		}
		ids = append(ids, id)
	}
	return nil, false
}
func idlePnPPresence(ctx context.Context) idlePresence {
	ids, ok := idlePnPIDs(ctx)
	p := idlePresenceFromIDs(ids, ok)
	monitorDiagnostics.presence(p)
	return p
}
func idleUSBPresence(ctx context.Context) (string, idlePresence) {
	ids, ok := idlePnPIDs(ctx)
	kind, p := idleUSBPresenceFromIDs(onlyIPadIDs(ids), ok)
	monitorDiagnostics.presence(p)
	return kind, p
}
func WaitForUSBConnection(ctx context.Context) string {
	for ctx.Err() == nil {
		if UnpairedExperimentPending() {
			return "iPad unpaired experiment"
		}
		if IPadSoftwareReconnectPending() {
			return "iPad software reconnect"
		}
		if IPadCandidatePending() {
			return "iPad candidate"
		}
		if NetworkOnlyPending() {
			return "iPad settings"
		}
		if AMDSModeDiagnosticPending() {
			return "iPad diagnostic"
		}
		if IPadModeDiagnosticHeld() {
			return "iPad diagnostic hold"
		}
		kind, p := idleUSBPresence(ctx)
		if p.candidate && !AMDSModeDiagnosticActive() && NetworkOnlyCanConnect() && IPadSoftwareReconnectCanConnect() {
			lastAttemptIdentity.Store(p.identity)
			return kind
		}
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ""
		case <-connectionChanged:
			timer.Stop()
		case <-timer.C:
		}
	}
	return ""
}

func WaitForIPadConnection(ctx context.Context) bool {
	for ctx.Err() == nil {
		if idlePnPPresence(ctx).candidate {
			return true
		}
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-connectionChanged:
			timer.Stop()
		case <-timer.C:
		}
	}
	return false
}

// Same-device transient failures get a bounded recovery budget, while detach
// and device-swap gates retain their debounce and identity checks.
func WaitAfterIPadAttempt(ctx context.Context, err string, applicationRan bool) bool {
	return waitAfterUSBAttempt(ctx, err, applicationRan, false)
}
func WaitAfterUSBAttempt(ctx context.Context, err string, applicationRan bool) bool {
	return waitAfterUSBAttempt(ctx, err, applicationRan, true)
}
func waitAfterUSBAttempt(ctx context.Context, err string, applicationRan, unified bool) bool {
	select {
	case <-connectionRetry:
	default:
	}
	SetMonitorStatus("MONITOR_PAUSED", err)
	delay := automaticRetries.delay(err, applicationRan)
	if !unified {
		delay = 0
	}
	due := time.Now().Add(delay)
	var stable sameAttachmentGate
	var gate idleReconnectGate
	var newDevice idleNewDeviceGate
	var reattach idleReattachGate
	previous, _ := lastAttemptIdentity.Load().(string)
	if unified {
		gate.minimum = 15 * time.Second
	}
	for ctx.Err() == nil {
		if UnpairedExperimentPending() {
			return true
		}
		if IPadSoftwareReconnectPending() {
			return true
		}
		if IPadCandidatePending() {
			return true
		}
		if NetworkOnlyPending() {
			return true
		}
		if AMDSModeDiagnosticPending() || IPadModeDiagnosticHeld() {
			return true
		}
		var p idlePresence
		if unified {
			_, p = idleUSBPresence(ctx)
		} else {
			p = idlePnPPresence(ctx)
		}
		now := time.Now()
		if gate.detached(now, p) || (unified && (newDevice.ready(now, previous, p) || reattach.ready(now, previous, p, applicationRan))) {
			automaticRetries = autoRetryBudget{}
			sameAttachmentRetry.Store(false)
			return true
		}
		if delay > 0 {
			ready := stable.ready(now, previous, p)
			remaining := max(0, int(time.Until(due).Seconds()+0.999))
			if m := connectionMonitor(); m != nil {
				m.update(func(r *ApplicationResult) {
					r.Status = "MONITOR_RETRYING"
					r.AutoRetryAttempt = automaticRetries.used + 1
					r.AutoRetrySeconds = remaining
				})
			}
			if ready && !now.Before(due) {
				automaticRetries.used++
				recordAutomaticRetry(err)
				sameAttachmentRetry.Store(true)
				return true
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-connectionRetry:
			timer.Stop()
			automaticRetries = autoRetryBudget{}
			sameAttachmentRetry.Store(p.readable && p.candidate && p.identity == previous)
			return ctx.Err() == nil
		case <-connectionChanged:
			timer.Stop()
		case <-timer.C:
		}
	}
	return false
}
