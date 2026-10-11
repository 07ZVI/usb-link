//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

var observedIPadModeProofs candidateProofGate

// Serialize only admission of fixed iPad actions, never USB/service operations.
var ipadActionAdmission sync.Mutex
var ipadCandidateControl struct {
	sync.Mutex
	stage, requested       int
	pending, busy, blocked bool
	scope, problem         string
}

type IPadCandidateStatus struct {
	Stage                  int               `json:"stage"`
	Pending                bool              `json:"pending"`
	Busy                   bool              `json:"busy"`
	Blocked                bool              `json:"blocked"`
	Problem                string            `json:"problem,omitempty"`
	DualModeSwitchVerified bool              `json:"two_observed_mode_switches_on_same_ipad"`
	Features               CandidateFeatures `json:"features"`
	NetworkOnly            NetworkOnlyStatus `json:"network_only"`
}

func RecordCurrentAMDSModeProof() {
	amdsDiagnosticJob.Lock()
	r, root, active := amdsDiagnosticJob.Result, amdsDiagnosticJob.TargetRoot, amdsDiagnosticJob.Running
	amdsDiagnosticJob.Unlock()
	if active || r == nil {
		return
	}
	p := candidateModeProof{Root: root, State: r.RequestedState, ServiceState: r.During, Restored: r.Restored, Error: r.Error, RestoreError: r.RestoreError}
	if m := r.Mode; m != nil {
		p.Status, p.Requested, p.Acknowledged, p.Reenumerated, p.USBIdentity = m.Status, m.SetAttempted, m.SetAcknowledged, m.ReenumerationSeen, m.USBIdentifiersVerified
		p.NCM = m.After != nil && HasActiveNCM(*m.After) && strings.EqualFold(exactIPadRoot(m.Before), root) && strings.EqualFold(exactIPadRoot(*m.After), root)
	}
	observedIPadModeProofs.record(p)
}

func IPadModeSwitchVerified() bool { _, ok := observedIPadModeProofs.scope(); return ok }
func IPadModeSwitchVerifiedForCurrentDevice() bool {
	ctx := connectionContext()
	root, ok := observedIPadModeProofs.scope()
	if !ok {
		return false
	}
	ids, complete := idlePnPIDs(ctx)
	_, p := idleUSBPresenceFromIDs(onlyIPadIDs(ids), complete)
	return complete && strings.EqualFold(root, p.identity)
}
func IPadCandidatePending() bool {
	ipadCandidateControl.Lock()
	defer ipadCandidateControl.Unlock()
	return ipadCandidateControl.pending
}
func IPadCandidateBusy() bool {
	ipadCandidateControl.Lock()
	defer ipadCandidateControl.Unlock()
	return ipadCandidateControl.pending || ipadCandidateControl.busy
}
func IPadCandidateCanConnect() bool {
	ipadCandidateControl.Lock()
	defer ipadCandidateControl.Unlock()
	return !ipadCandidateControl.blocked && !ipadCandidateControl.pending && !ipadCandidateControl.busy
}

func BlockIPadCandidate(problem string) {
	ipadCandidateControl.Lock()
	ipadCandidateControl.blocked, ipadCandidateControl.problem = true, problem
	ipadCandidateControl.Unlock()
}

// Features are process-local, but their authority is restricted to one device.
// Call after USB consent and before any preparation or persistent changes.
func ValidateIPadCandidateDevice() error {
	ipadCandidateControl.Lock()
	stage, root := ipadCandidateControl.stage, ipadCandidateControl.scope
	ipadCandidateControl.Unlock()
	if stage == 0 {
		return nil
	}
	ids, complete := idlePnPIDs(connectionContext())
	_, p := idleUSBPresenceFromIDs(onlyIPadIDs(ids), complete)
	proofRoot, proven := observedIPadModeProofs.scope()
	if !complete || !proven || !strings.EqualFold(root, p.identity) || !strings.EqualFold(root, proofRoot) {
		err := fmt.Errorf("candidate features require the same mode-verified iPad; restore candidate settings first")
		BlockIPadCandidate(err.Error())
		return err
	}
	return nil
}
func IPadCandidateSnapshot() IPadCandidateStatus {
	ipadCandidateControl.Lock()
	s := IPadCandidateStatus{Stage: ipadCandidateControl.stage, Pending: ipadCandidateControl.pending, Busy: ipadCandidateControl.busy, Blocked: ipadCandidateControl.blocked, Problem: ipadCandidateControl.problem}
	ipadCandidateControl.Unlock()
	s.DualModeSwitchVerified = IPadModeSwitchVerified()
	s.Features = IPadCandidateFeatures()
	s.NetworkOnly = NetworkOnlySnapshot()
	return s
}

// Fixed stages only, queued behind full cleanup of the current iPad attempt.
// A requested stage cannot create or import evidence to satisfy the mode gate.
func RequestIPadCandidateStage(stage int) error {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	if SimplifiedIPadNetworkConfigured() {
		return fmt.Errorf("legacy isolation candidates retired; simplified USB networking uses fresh device consent")
	}
	if UnpairedExperimentBusy() {
		return fmt.Errorf("unpaired experiment owner active")
	}
	if ipadUpgradeReserved.Load() {
		return fmt.Errorf("signed maintenance upgrade reserved")
	}
	if IPadSoftwareReconnectAdmissionBusy() || !IPadSoftwareReconnectCanConnect() {
		return fmt.Errorf("software reconnect or its restoration unresolved")
	}
	// The owner waits for process termination after failed cleanup. It cannot
	// consume a new request there; do not create a permanent upgrade blocker.
	if s := connectionMonitor(); s != nil && s.snapshot().Status == "USB_RECOVERY_WAITING" {
		return fmt.Errorf("iPad cleanup unresolved; restart the program to recover before requesting settings")
	}
	if AMDSModeDiagnosticActive() || NetworkOnlySnapshot().Busy {
		return fmt.Errorf("iPad action already running")
	}
	root, proven := observedIPadModeProofs.scope()
	if stage != 0 && !proven {
		return fmt.Errorf("two actual AMDS running/stopped mode switches must pass first")
	}
	ipadCandidateControl.Lock()
	if ipadCandidateControl.pending || ipadCandidateControl.busy || !nextIPadCandidateStage(ipadCandidateControl.stage, stage) {
		ipadCandidateControl.Unlock()
		return fmt.Errorf("candidate stage busy or out of order")
	}
	ipadCandidateControl.requested, ipadCandidateControl.pending, ipadCandidateControl.scope = stage, true, root
	ipadCandidateControl.Unlock()
	amdsDiagnosticJob.Lock()
	stop := amdsDiagnosticJob.AttemptStop
	amdsDiagnosticJob.Unlock()
	time.AfterFunc(200*time.Millisecond, func() {
		if stop != nil {
			stop()
		}
		signalDiagnosticLoop()
	})
	return nil
}

func RunPendingIPadCandidate(ctx context.Context, dir, system string, cleanupSafe bool) bool {
	ipadCandidateControl.Lock()
	if !ipadCandidateControl.pending || ipadUpgradeReserved.Load() {
		ipadCandidateControl.Unlock()
		return false
	}
	stage, root := ipadCandidateControl.requested, ipadCandidateControl.scope
	ipadCandidateControl.pending, ipadCandidateControl.busy = false, true
	ipadCandidateControl.Unlock()
	var err error
	if !cleanupSafe || ctx.Err() != nil {
		err = fmt.Errorf("previous iPad cleanup unresolved or cancelled")
	} else if stage == 0 {
		err = RecoverAMDSModeDiagnostic(dir)
		if err == nil {
			r := RecoverApplicationSession(dir, system)
			if r.Error != "" || r.Pending && !r.JournalCleared {
				err = fmt.Errorf("application recovery unconfirmed: %s", r.Error)
			}
		}
		if err == nil {
			err = RestoreNetworkOnlyPortableNodes(dir)
		}
		if err == nil {
			r := RecoverGrouping(dir, system)
			if r.Error != "" || r.RebootRequired || r.Pending && !r.JournalCleared {
				err = fmt.Errorf("grouping recovery unconfirmed: %s", r.Error)
			}
		}
		if err == nil {
			err = RestoreNetworkOnly(dir, system)
		}
		if err == nil {
			err = InitNetworkOnly(dir, system, false)
		}
		if err == nil {
			SetIPadCandidateStage(0)
		}
	} else {
		ids, complete := idlePnPIDs(ctx)
		_, presence := idleUSBPresenceFromIDs(onlyIPadIDs(ids), complete)
		if !complete || !strings.EqualFold(presence.identity, root) || !IPadModeSwitchVerified() {
			err = fmt.Errorf("same connected, mode-verified iPad required")
		} else if stage == 5 {
			err = InitNetworkOnly(dir, system, true)
		} else if !SetIPadCandidateStage(stage) {
			err = fmt.Errorf("invalid candidate stage")
		}
	}
	ipadCandidateControl.Lock()
	ipadCandidateControl.busy, ipadCandidateControl.blocked = false, err != nil
	if err != nil {
		ipadCandidateControl.problem = err.Error()
	} else {
		ipadCandidateControl.stage, ipadCandidateControl.problem = stage, ""
	}
	ipadCandidateControl.Unlock()
	if err == nil && (stage == 0 || stage == 3) {
		ReleaseIPadModeDiagnosticHoldAfterRecovery(true)
	}
	signalDiagnosticLoop()
	return true
}

// A settings error pauses only iPad; the independent Mac management remains.
// Device or settings events wake this wait without adding a polling timer.
func WaitForIPadSettingsRecovery(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-connectionChanged:
		return true
	}
}

func EnsureCurrentNetworkOnly() error {
	return EnsureCurrentNetworkOnlyForPhase("unspecified_ensure")
}

func EnsureCurrentNetworkOnlyForPhase(phase string) error {
	if !NetworkOnlyEnabled() {
		return nil
	}
	return EnsureNetworkOnlyForPhase(connectionContext(), Inspect(), phase)
}
