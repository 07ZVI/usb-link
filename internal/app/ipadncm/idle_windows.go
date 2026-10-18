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
		archiveOwnerNotice("queued", "coalesced_owner_signal", code)
	default:
		archiveOwnerNotice("coalesced", "coalesced_owner_signal", code)
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
	archiveOwnerPhase("candidate_wait", "begin")
	defer func() {
		if ctx.Err() != nil {
			archiveOwnerPhase("candidate_wait", "cancelled")
		} else {
			archiveOwnerPhase("candidate_wait", "end")
		}
	}()
	connectionTimingWaitBegin()
	var lastPresence idlePresence
	havePresence := false
	haveProductGate, lastProductAllowed := false, false
	var lastRootState string
	var lastRootObservation idleRootObservation
	for ctx.Err() == nil {
		connectionTimingOwnerLoop()
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
		plan := connectionTimingWaitPlan()
		kind, p := idleUSBPresence(ctx)
		if !havePresence || p != lastPresence {
			archiveCandidate("cached_presence_observed", p, false)
			lastPresence, havePresence = p, true
		}
		productAllowed := p.candidate && !AMDSModeDiagnosticActive() && NetworkOnlyCanConnect() && IPadSoftwareReconnectCanConnect()
		if p.candidate && (!haveProductGate || productAllowed != lastProductAllowed) {
			archiveCandidate("pre_candidate_product_gate", p, productAllowed)
			haveProductGate, lastProductAllowed = true, productAllowed
		}
		if productAllowed {
			acceptedKind, acceptedPresence, accepted := connectionTimingAccept(ctx, plan, kind, p)
			diagnosticPresence := p
			if accepted {
				diagnosticPresence = acceptedPresence
			}
			archiveCandidate("timing_and_candidate_check", diagnosticPresence, accepted)
			if !accepted {
				continue
			}
			if !connectionTimingCandidateAllowed() {
				archiveCandidate("final_product_gate", acceptedPresence, false)
				continue
			}
			rootReady := true
			if acceptedKind == "iPad" {
				state, observation := idleExactRootReadiness(ctx, acceptedPresence.identity)
				rootReady = state == "root_started_not_authorization"
				if state != lastRootState || observation != lastRootObservation {
					RecordConnectionArchiveEvent("candidate_gate", struct {
						Phase         string `json:"phase"`
						Reason        string `json:"reason"`
						Allowed       bool   `json:"allowed"`
						ContextActive bool   `json:"context_active"`
						ExactRoot     bool   `json:"exact_root"`
						StateReadable bool   `json:"state_readable"`
						Status        uint32 `json:"status"`
						Problem       uint32 `json:"problem"`
					}{"cached_root_readiness", state, rootReady, observation.ContextActive, observation.ExactRoot, observation.StateReadable, observation.Status, observation.Problem})
					lastRootState, lastRootObservation = state, observation
				}
			}
			if rootReady && ctx.Err() == nil && connectionTimingCandidateAllowed() {
				archiveCandidate("accepted_for_attempt_not_usb_authorization", acceptedPresence, true)
				lastAttemptIdentity.Store(acceptedPresence.identity)
				return acceptedKind
			}
		}
		timer := time.NewTimer(plan.fallback)
		select {
		case <-ctx.Done():
			timer.Stop()
			connectionTimingWake("context_cancelled")
			return ""
		case <-plan.changed:
			timer.Stop()
			connectionTimingWake("profile_changed")
		case <-connectionChanged:
			timer.Stop()
			archiveOwnerNotice("consumed", "candidate_wait", 0)
			connectionTimingWake("owner_notice")
		case <-timer.C:
			connectionTimingWake("fallback")
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
	archiveOwnerPhase("rearm_wait", "begin")
	defer func() {
		if ctx.Err() != nil {
			archiveOwnerPhase("rearm_wait", "cancelled")
		} else {
			archiveOwnerPhase("rearm_wait", "end")
		}
	}()
	waitStarted := time.Now()
	var lastDiagnostic rearmDiagnosticSample
	haveDiagnostic := false
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
		// Preserve the original short-circuit order; diagnostics only observe
		// states already updated by the existing readiness gates.
		detached, newReady, sameReady := gate.detached(now, p), false, false
		if !detached && unified {
			newReady = newDevice.ready(now, previous, p)
			if !newReady {
				sameReady = reattach.ready(now, previous, p, applicationRan)
			}
		}
		diagnostic := rearmDiagnostic(now, waitStarted, previous, p, applicationRan, reattach, detached, newReady, sameReady)
		diagnostic.Attempt = currentSoftwareAttempt()
		if !haveDiagnostic || !sameRearmDiagnosticState(lastDiagnostic, diagnostic) {
			RecordConnectionArchiveEvent("rearm_gate", diagnostic)
			lastDiagnostic, haveDiagnostic = diagnostic, true
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
				archiveOwnerPhase("automatic_retry_ready", "observed")
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
			archiveOwnerPhase("manual_retry_requested", "consumed")
			automaticRetries = autoRetryBudget{}
			sameAttachmentRetry.Store(p.readable && p.candidate && p.identity == previous)
			return ctx.Err() == nil
		case <-connectionChanged:
			timer.Stop()
			archiveOwnerNotice("consumed", "rearm_wait", 0)
		case <-timer.C:
		}
	}
	return false
}

func connectionTimingCandidateAllowed() bool {
	return !(UnpairedExperimentPending() || IPadSoftwareReconnectPending() || IPadCandidatePending() || NetworkOnlyPending() || AMDSModeDiagnosticPending() || IPadModeDiagnosticHeld() || AMDSModeDiagnosticActive() || !NetworkOnlyCanConnect() || !IPadSoftwareReconnectCanConnect())
}
