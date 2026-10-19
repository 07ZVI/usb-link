//go:build windows && amd64

package ipadncm

import (
	"context"
	"golang.org/x/sys/windows"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
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

func idleExactRootReadiness(ctx context.Context, expected string) (string, idleRootObservation) {
	_, before := idleUSBPresence(ctx)
	o := idleRootObservation{ContextActive: ctx.Err() == nil}
	if o.ContextActive && before.readable && before.candidate && before.identity == expected {
		p, err := windows.UTF16PtrFromString(expected)
		if err == nil {
			var dev windows.DEVINST
			cr, _, _ := portableCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&dev)), uintptr(unsafe.Pointer(p)), 0)
			if cr == 0 {
				var id [1024]uint16
				idCR, _, _ := portableID.Call(uintptr(dev), uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)), 0)
				o.ExactRoot = idCR == 0 && strings.EqualFold(windows.UTF16ToString(id[:]), expected)
				if o.ExactRoot {
					o.StateReadable = windows.CM_Get_DevNode_Status(&o.Status, &o.Problem, dev, 0) == nil
				}
			}
		}
	}
	_, after := idleUSBPresence(ctx)
	o.ContextActive = ctx.Err() == nil
	return idleRootReadiness(expected, before, after, o), o
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
		productAllowed := p.candidate && !AMDSModeDiagnosticActive() && NetworkOnlyCanConnect() && IPadSoftwareReconnectCanConnect()
		if productAllowed {
			if ctx.Err() != nil {
				continue
			}
			acceptedKind, acceptedPresence := kind, p
			if !idleConnectionAllowed() {
				continue
			}
			rootReady := true
			if acceptedKind == "iPad" {
				state, _ := idleExactRootReadiness(ctx, acceptedPresence.identity)
				rootReady = state == "root_started_not_authorization"
			}
			if rootReady && ctx.Err() == nil && idleConnectionAllowed() {
				lastAttemptIdentity.Store(acceptedPresence.identity)
				return acceptedKind
			}
		}
		timer := time.NewTimer(time.Second)
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
	if unified && err != "" {
		outcome := authorizationOutcomeSnapshot()
		attemptFailures.record(attemptFailureRecord{SoftwareAttempt: currentSoftwareAttempt(), Code: err, ConsentStatus: outcome.Status, ReadErrorCodes: outcome.Details, ApplicationRan: applicationRan, AutoRetryEligible: delay > 0}, time.Now())
	}
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
		// Preserve the short-circuit order of the readiness gates.
		detached, newReady, sameReady := gate.detached(now, p), false, false
		if !detached && unified {
			newReady = newDevice.ready(now, previous, p)
			if !newReady {
				sameReady = reattach.ready(now, previous, p, applicationRan)
			}
		}
		if detached || newReady || sameReady {
			if detached || newReady {
				attemptFailures.newAttachment()
			}
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

func idleConnectionAllowed() bool {
	return !(UnpairedExperimentPending() || IPadSoftwareReconnectPending() || IPadCandidatePending() || NetworkOnlyPending() || AMDSModeDiagnosticPending() || IPadModeDiagnosticHeld() || AMDSModeDiagnosticActive() || !NetworkOnlyCanConnect() || !IPadSoftwareReconnectCanConnect())
}
