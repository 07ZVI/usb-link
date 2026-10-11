package remoteupdate

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// StartupEvidence separates deployment from an authenticated normal USB-ready
// acknowledgement. A repair listener is useful, but is never normal readiness.
type StartupEvidence struct {
	MatchingAck bool
	USBState    string
	Alive       bool
}
type StartupDecision string

const (
	StartupWait     StartupDecision = "wait"
	StartupComplete StartupDecision = "complete"
	StartupRecovery StartupDecision = "deployed_recovery_required"
	StartupRollback StartupDecision = "rollback"
	StartupStop     StartupDecision = "graceful_stop_required"
)

type StartupTracker struct {
	acknowledged time.Time
	kind         string
}

func (s *StartupTracker) Observe(now time.Time, e StartupEvidence, deadline bool) StartupDecision {
	if !e.Alive {
		return StartupRollback
	}
	if e.MatchingAck && (e.USBState == "verified" || e.USBState == "recovery_required") {
		if s.kind != e.USBState || s.acknowledged.IsZero() {
			s.acknowledged = now
			s.kind = e.USBState
		}
		if now.Sub(s.acknowledged) >= 5*time.Second {
			if e.USBState == "verified" {
				return StartupComplete
			}
			return StartupRecovery
		}
	} else {
		s.acknowledged = time.Time{}
		s.kind = ""
	}
	if deadline {
		return StartupStop
	}
	return StartupWait
}
func UpdateInFlight(status string) bool {
	switch status {
	case "awaiting_local_approval", "awaiting_auto_install", "handoff", "starting", "rollback", "manual_recovery_required":
		return true
	}
	return false
}
func RetryableJob(status string) bool {
	switch status {
	case "staged", "failed", "cancelled", "declined", "interrupted", "rollback_running", "rollback_failed", "complete", "deployed_recovery_required", "manual_recovery_required":
		return true
	}
	return false
}

// ClassifyJob only permits stale-owner recovery when an owner was recorded and
// its exact process identity is known to have exited. Unknown identity fails shut.
func ClassifyJob(status string, ownerRecorded, ownerAlive bool) (block bool, interrupted bool) {
	if !UpdateInFlight(status) {
		return false, false
	}
	if !ownerRecorded || ownerAlive {
		return true, false
	}
	return false, true
}

// ReserveIdleActions is called while the owner locks cover both queues. It never
// authorizes USB mutations and does not inspect, delete, or change durable state.
func ReserveIdleActions(candidatePending, candidateBusy, networkPending, networkBusy, amdsActive, reserved bool) (cancelCandidate, cancelNetwork, accepted bool) {
	if candidateBusy || networkBusy || amdsActive || reserved {
		return false, false, false
	}
	return candidatePending, networkPending, true
}

func JobTransitionAllowed(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case "staged":
		return to == "awaiting_local_approval" || to == "awaiting_auto_install" || to == "cancelled" || to == "failed"
	case "awaiting_local_approval", "awaiting_auto_install":
		return to == "handoff" || to == "declined" || to == "failed" || to == "cancelled" || to == "interrupted"
	case "handoff":
		return to == "starting" || to == "failed" || to == "rollback" || to == "interrupted"
	case "starting":
		return to == "complete" || to == "deployed_recovery_required" || to == "rollback" || to == "manual_recovery_required" || to == "interrupted"
	case "manual_recovery_required":
		return to == "interrupted"
	case "rollback":
		return to == "rollback_running" || to == "rollback_failed" || to == "interrupted"
	}
	return false
}

// A job writer owns both the opaque ID and the exact producing process. PID
// reuse, an old legacy worker and a late approval cannot mutate its replacement.
type JobIdentity struct {
	ID, Status, Executable string
	Guarded                bool
	PID                    uint32
	Creation               uint64
}

func JobIdentityValid(j JobIdentity) bool {
	b, err := hex.DecodeString(j.ID)
	return err == nil && len(b) == 16 && (!j.Guarded || j.PID != 0 && j.Creation != 0 && j.Executable != "")
}
func JobWriteAllowed(current, next JobIdentity, workerTransfer bool) bool {
	if !JobIdentityValid(next) {
		return false
	}
	if current.ID != next.ID {
		return JobIdentityValid(current) && next.Status == "staged" && !UpdateInFlight(current.Status)
	}
	if current.Guarded {
		if !next.Guarded {
			return false
		}
		sameOwner := current.PID == next.PID && current.Creation == next.Creation && current.Executable == next.Executable
		if !sameOwner && !(workerTransfer && current.Status == "handoff" && next.Status == "handoff" && current.Executable == next.Executable) {
			return false
		}
	}
	return JobTransitionAllowed(current.Status, next.Status)
}

// Normal health acks must be refreshed by the already-admitted Mac monitor;
// five seconds of process survival cannot make a stale USB snapshot healthy.
func StartupAckMatches(ack map[string]string, id, version string, pid int, now time.Time) bool {
	if ack["id"] != id || ack["version"] != version || ack["pid"] != fmt.Sprint(pid) {
		return false
	}
	if ack["usb_state"] != "verified" {
		return true
	}
	stamp, err := strconv.ParseInt(ack["observed_at_unix_nano"], 10, 64)
	age := now.Sub(time.Unix(0, stamp))
	return err == nil && age >= 0 && age <= 3*time.Second
}

// A timed-out startup can be repaired only after both the old worker and its
// recorded candidate have demonstrably exited; unknown evidence fails shut.
func ClassifyRepair(status string, workerKnown, workerAlive, candidateKnown, candidateAlive bool) (bool, bool) {
	if (status == "starting" || status == "manual_recovery_required") && (!candidateKnown || candidateAlive) {
		return true, false
	}
	return ClassifyJob(status, workerKnown, workerAlive)
}

// ReportProgress separates the deployed candidate from the current process's
// independent Mac connection. An iPad's selected monitor never enters it.
func ReportProgress(persisted, candidateVersion, currentVersion string, macHealthy, recoveryOnly bool) (status, deployment, usb string) {
	status = persisted
	deployment = "pending"
	usb = "unverified"
	if macHealthy && !recoveryOnly {
		usb = "verified"
	} else if recoveryOnly {
		usb = "recovery_required"
	}
	switch persisted {
	case "complete", "deployed_recovery_required":
		deployment = "installed"
		if candidateVersion != currentVersion {
			status = "deployed_not_running"
		} else if usb != "verified" {
			status = "deployed_recovery_required"
			usb = "recovery_required"
		}
	case "rollback_running":
		deployment = "previous_process_running"
	case "rollback_failed":
		deployment = "previous_process_unavailable"
	case "manual_recovery_required":
		deployment = "startup_unconfirmed"
	case "failed":
		deployment = "failed"
	case "interrupted":
		deployment = "interrupted"
	case "cancelled", "declined":
		deployment = "cancelled"
	}
	return
}

// Copying a stored owner into a write does not confer that owner's identity.
func OrdinaryWriterAllowed(j JobIdentity, pid uint32, creation uint64, executable string) bool {
	return !j.Guarded || j.PID == pid && j.Creation == creation && j.Executable == executable
}

// RunRollback commits ownership before starting an old process and propagates
// every failed durable transition, including the final health/error record.
type RollbackResult struct {
	Status, Detail string
	Err            error
}

func RunRollback(reason string, save func(string, string) error, restore func() RollbackResult) error {
	if err := save("rollback", reason); err != nil {
		return err
	}
	result := restore()
	if result.Status != "rollback_running" && result.Status != "rollback_failed" {
		return fmt.Errorf("invalid rollback outcome")
	}
	if err := save(result.Status, result.Detail); err != nil {
		return err
	}
	return result.Err
}
