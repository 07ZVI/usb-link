package remoteupdate

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStartupNeedsMatchingNormalUSBHealthAndContinuousEvidence(t *testing.T) {
	base := time.Unix(100, 0)
	var s StartupTracker
	// A live TLS listener without the exact child's normal USB acknowledgement
	// is not health; timeout requires graceful stop, not a successful update.
	if got := s.Observe(base, StartupEvidence{Alive: true}, false); got != StartupWait {
		t.Fatal(got)
	}
	if got := s.Observe(base.Add(time.Minute), StartupEvidence{Alive: true}, true); got != StartupStop {
		t.Fatal(got)
	}
	recovery := StartupEvidence{Alive: true, MatchingAck: true, USBState: "recovery_required"}
	if got := s.Observe(base, recovery, false); got != StartupWait {
		t.Fatal(got)
	}
	if got := s.Observe(base.Add(5*time.Second), recovery, false); got != StartupRecovery {
		t.Fatal("recovery-only reported complete", got)
	}
	good := StartupEvidence{Alive: true, MatchingAck: true, USBState: "verified"}
	s = StartupTracker{}
	s.Observe(base, good, false)
	s.Observe(base.Add(4*time.Second), StartupEvidence{Alive: true, USBState: "verified"}, false)
	if got := s.Observe(base.Add(5*time.Second), good, false); got != StartupWait {
		t.Fatal("stale child ack did not reset health", got)
	}
	if got := s.Observe(base.Add(10*time.Second), good, false); got != StartupComplete {
		t.Fatal(got)
	}
	if got := s.Observe(base.Add(11*time.Second), StartupEvidence{Alive: false}, false); got != StartupRollback {
		t.Fatal(got)
	}
}

func TestInterruptedOwnerRetryDoesNotAdmitActiveOrUnknownProcess(t *testing.T) {
	for _, status := range []string{"awaiting_auto_install", "awaiting_local_approval", "handoff", "starting", "rollback", "manual_recovery_required"} {
		for _, owner := range []struct{ known, alive bool }{{false, false}, {true, true}} {
			block, interrupted := ClassifyJob(status, owner.known, owner.alive)
			if !block || interrupted {
				t.Fatalf("%s accepted ambiguous/live owner", status)
			}
		}
		block, interrupted := ClassifyJob(status, true, false)
		if block || !interrupted {
			t.Fatalf("%s permanent dead-owner blocker", status)
		}
		if !JobTransitionAllowed(status, "interrupted") {
			t.Fatal("dead owner could not be recorded durably", status)
		}
	}
}

func TestLateWorkerCannotOverwriteReplacementOrBorrowGuardedIdentity(t *testing.T) {
	first := JobIdentity{ID: strings.Repeat("a", 32), Status: "handoff", Guarded: true, PID: 100, Creation: 10, Executable: "owned.exe"}
	worker := first
	worker.PID = 101
	worker.Creation = 11
	if JobWriteAllowed(first, worker, false) || !JobWriteAllowed(first, worker, true) {
		t.Fatal("only explicit worker transfer may replace owner")
	}
	// Old approval callback still knows the ID, but no longer owns its process.
	parentLate := first
	parentLate.Status = "failed"
	if JobWriteAllowed(worker, parentLate, false) {
		t.Fatal("old parent overwrote worker")
	}
	legacy := worker
	legacy.Guarded = false
	legacy.Status = "failed"
	if JobWriteAllowed(worker, legacy, false) {
		t.Fatal("legacy worker borrowed guarded identity")
	}
	reusedPID := worker
	reusedPID.Creation++
	if JobWriteAllowed(worker, reusedPID, false) {
		t.Fatal("PID reuse accepted")
	}
	if JobWriteAllowed(worker, JobIdentity{ID: strings.Repeat("b", 32), Status: "staged"}, false) {
		t.Fatal("executing upgrade replaced")
	}
	terminal := worker
	terminal.Status = "failed"
	next := JobIdentity{ID: strings.Repeat("b", 32), Status: "staged", Guarded: true, PID: 102, Creation: 12, Executable: "owned.exe"}
	if !JobWriteAllowed(terminal, next, false) {
		t.Fatal("failed update not retryable")
	}
	oldDone := worker
	oldDone.Status = "complete"
	if JobWriteAllowed(next, oldDone, false) {
		t.Fatal("history writer overwrote replacement")
	}
	malformed := terminal
	malformed.ID = "../" + strings.Repeat("x", 29)
	if JobWriteAllowed(malformed, next, false) {
		t.Fatal("unsafe history identity accepted")
	}
}

func TestRecoveryStartupFailureRollbackAndUnavailableRemainDistinct(t *testing.T) {
	for _, terminal := range []string{"complete", "deployed_recovery_required", "rollback", "manual_recovery_required"} {
		if !JobTransitionAllowed("starting", terminal) {
			t.Fatal(terminal)
		}
	}
	if JobTransitionAllowed("deployed_recovery_required", "complete") || JobTransitionAllowed("failed", "complete") {
		t.Fatal("terminal failure rewritten as successful deployment")
	}
	for _, state := range []string{"rollback_running", "rollback_failed"} {
		if !JobTransitionAllowed("rollback", state) || !RetryableJob(state) {
			t.Fatal(state)
		}
	}
}

func TestTimedOutRepairNeedsWorkerAndCandidateExitBeforeRetry(t *testing.T) {
	for _, state := range []string{"starting", "manual_recovery_required"} {
		for _, c := range []struct {
			wk, wa, ck, ca bool
			allow          bool
		}{
			{true, false, true, false, true},
			{false, false, true, false, false},
			{true, true, true, false, false},
			{true, false, false, false, false},
			{true, false, true, true, false},
		} {
			block, interrupted := ClassifyRepair(state, c.wk, c.wa, c.ck, c.ca)
			if block == c.allow || interrupted != c.allow {
				t.Fatalf("%s %+v block=%v interrupted=%v", state, c, block, interrupted)
			}
		}
	}
}
func TestStartupAckRequiresExactChildAndFreshMacHealth(t *testing.T) {
	now := time.Unix(100, 0)
	ack := map[string]string{"id": "job", "version": "v", "pid": "11", "usb_state": "verified", "observed_at_unix_nano": fmt.Sprint(now.UnixNano())}
	if !StartupAckMatches(ack, "job", "v", 11, now) {
		t.Fatal("matching fresh ack rejected")
	}
	if StartupAckMatches(ack, "job", "v", 12, now) || StartupAckMatches(ack, "old", "v", 11, now) || StartupAckMatches(ack, "job", "v", 11, now.Add(4*time.Second)) {
		t.Fatal("different/stale ack accepted")
	}
	ack["observed_at_unix_nano"] = fmt.Sprint(now.Add(time.Second).UnixNano())
	if StartupAckMatches(ack, "job", "v", 11, now) {
		t.Fatal("future health timestamp accepted")
	}
	ack["usb_state"] = "recovery_required"
	delete(ack, "observed_at_unix_nano")
	var tracker StartupTracker
	if !StartupAckMatches(ack, "job", "v", 11, now) {
		t.Fatal("deployment-only acknowledgement rejected")
	}
	tracker.Observe(now, StartupEvidence{Alive: true, MatchingAck: true, USBState: ack["usb_state"]}, false)
	if got := tracker.Observe(now.Add(5*time.Second), StartupEvidence{Alive: true, MatchingAck: true, USBState: ack["usb_state"]}, false); got != StartupRecovery {
		t.Fatal("repair listener incorrectly became USB complete", got)
	}
}

func TestProgressNeverConfusesDeploymentCurrentVersionOrMacRecovery(t *testing.T) {
	for _, c := range []struct {
		stored, candidate, current string
		healthy, recovery          bool
		status, deployment, usb    string
	}{
		{"complete", "new", "new", false, false, "deployed_recovery_required", "installed", "recovery_required"},
		{"complete", "new", "old", true, false, "deployed_not_running", "installed", "verified"},
		{"complete", "new", "new", true, true, "deployed_recovery_required", "installed", "recovery_required"},
		{"complete", "new", "new", true, false, "complete", "installed", "verified"},
		{"rollback_running", "new", "old", false, false, "rollback_running", "previous_process_running", "unverified"},
		{"rollback_failed", "new", "old", false, false, "rollback_failed", "previous_process_unavailable", "unverified"},
		{"manual_recovery_required", "new", "new", false, true, "manual_recovery_required", "startup_unconfirmed", "recovery_required"},
	} {
		status, deployment, usb := ReportProgress(c.stored, c.candidate, c.current, c.healthy, c.recovery)
		if status != c.status || deployment != c.deployment || usb != c.usb {
			t.Fatalf("%+v got %s %s %s", c, status, deployment, usb)
		}
	}
}

func TestActualWriterCannotImpersonateStoredLiveParent(t *testing.T) {
	owner := JobIdentity{ID: strings.Repeat("a", 32), Status: "awaiting_auto_install", Guarded: true, PID: 100, Creation: 10, Executable: "owned.exe"}
	if OrdinaryWriterAllowed(owner, 101, 11, "owned.exe") {
		t.Fatal("new manager copied a live parent's owner fields")
	}
	if OrdinaryWriterAllowed(owner, 100, 12, "owned.exe") {
		t.Fatal("reused PID could write guarded authorization")
	}
	if !OrdinaryWriterAllowed(owner, 100, 10, "owned.exe") {
		t.Fatal("actual owner denied")
	}
	block, interrupted := ClassifyJob(owner.Status, true, true)
	if !block || interrupted {
		t.Fatal("startup manager interrupted live authorization")
	}
	block, interrupted = ClassifyJob(owner.Status, true, false)
	if block || !interrupted {
		t.Fatal("verified exited parent could not be archived as interrupted")
	}
}
func TestRollbackPersistenceFailureCannotLaunchOrReportSuccess(t *testing.T) {
	failed := errors.New("durable owner changed")
	current := JobIdentity{ID: strings.Repeat("a", 32), Status: "starting", Guarded: true, PID: 100, Creation: 10, Executable: "owned.exe"}
	restores := 0
	save := func(status, detail string) error {
		next := current
		next.Status = status
		if !JobWriteAllowed(current, next, false) {
			return failed
		}
		current = next
		return nil
	}
	// A replaced job denies the rollback marker. No old executable starts.
	if err := RunRollback("startup failure", func(string, string) error { return failed }, func() RollbackResult { restores++; return RollbackResult{Status: "rollback_running"} }); !errors.Is(err, failed) || restores != 0 {
		t.Fatal("stale rollback executed", err, restores)
	}
	// During restoration the worker still owns an in-flight job. An independent
	// new upload cannot replace it even though USB has not recovered yet.
	err := RunRollback("startup failure", save, func() RollbackResult {
		restores++
		replacement := current
		replacement.ID = strings.Repeat("b", 32)
		replacement.Status = "staged"
		if JobWriteAllowed(current, replacement, false) {
			t.Fatal("executing rollback replaced by new stage")
		}
		return RollbackResult{Status: "rollback_running", Detail: "old process alive; USB unverified"}
	})
	if err != nil || current.Status != "rollback_running" || restores != 1 {
		t.Fatal(err, current, restores)
	}
	// A failed final record must propagate rather than silently claiming restore.
	writes := 0
	err = RunRollback("startup failure", func(string, string) error {
		writes++
		if writes == 2 {
			return failed
		}
		return nil
	}, func() RollbackResult { return RollbackResult{Status: "rollback_running"} })
	if !errors.Is(err, failed) || writes != 2 {
		t.Fatal("final failed save reported successful recovery", err, writes)
	}
	// A signed previous process that exits early stays an explicit failure.
	err = RunRollback("startup failure", func(string, string) error { return nil }, func() RollbackResult { return RollbackResult{Status: "rollback_failed", Err: failed} })
	if !errors.Is(err, failed) {
		t.Fatal("old process failure hidden", err)
	}
}
