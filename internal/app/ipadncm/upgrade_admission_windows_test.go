//go:build windows && amd64

package ipadncm

import (
	"context"
	"sync"
	"testing"
)

func TestUpgradeCancelsOnlyIdleOwnedQueuesAndKeepsRecoveryState(t *testing.T) {
	// Package tests run without device setup. No platform mutation or durable
	// writer is involved in this callback; cancelled queues cannot be consumed.
	ipadCandidateControl.Lock()
	oldPending, oldBusy, oldBlocked := ipadCandidateControl.pending, ipadCandidateControl.busy, ipadCandidateControl.blocked
	oldStage, oldProblem := ipadCandidateControl.stage, ipadCandidateControl.problem
	ipadCandidateControl.pending, ipadCandidateControl.busy, ipadCandidateControl.blocked = true, false, true
	ipadCandidateControl.stage = 3
	ipadCandidateControl.Unlock()
	networkOnly.Lock()
	oldNetworkPending, oldNetworkBusy, oldEnabled, oldStatus := networkOnly.pending, networkOnly.busy, networkOnly.enabled, networkOnly.status
	networkOnly.pending, networkOnly.busy, networkOnly.enabled = true, false, true
	networkOnly.Unlock()
	amdsDiagnosticJob.Lock()
	oldRunning := amdsDiagnosticJob.Running
	amdsDiagnosticJob.Running = false
	amdsDiagnosticJob.Unlock()
	oldReserved := ipadUpgradeReserved.Load()
	ipadUpgradeReserved.Store(false)
	defer func() {
		ipadCandidateControl.Lock()
		ipadCandidateControl.pending, ipadCandidateControl.busy, ipadCandidateControl.blocked = oldPending, oldBusy, oldBlocked
		ipadCandidateControl.stage, ipadCandidateControl.problem = oldStage, oldProblem
		ipadCandidateControl.Unlock()
		networkOnly.Lock()
		networkOnly.pending, networkOnly.busy, networkOnly.enabled, networkOnly.status = oldNetworkPending, oldNetworkBusy, oldEnabled, oldStatus
		networkOnly.Unlock()
		amdsDiagnosticJob.Lock()
		amdsDiagnosticJob.Running = oldRunning
		amdsDiagnosticJob.Unlock()
		ipadUpgradeReserved.Store(oldReserved)
	}()
	release, err := reserveIPadUpgrade()
	if err != nil {
		t.Fatal(err)
	}
	if IPadCandidatePending() || NetworkOnlyPending() || !ipadUpgradeReserved.Load() {
		t.Fatal("idle queue was retained or no reservation")
	}
	ipadCandidateControl.Lock()
	unchanged := ipadCandidateControl.blocked && ipadCandidateControl.stage == 3
	ipadCandidateControl.Unlock()
	networkOnly.Lock()
	unchanged = unchanged && networkOnly.enabled
	networkOnly.Unlock()
	if !unchanged {
		t.Fatal("upgrade changed applied stage, recovery block or user choice")
	}
	if _, err = reserveIPadUpgrade(); err == nil {
		t.Fatal("duplicate reservation accepted")
	}
	if RunPendingIPadCandidate(context.Background(), "", "", true) || RunPendingNetworkOnly(context.Background(), true) {
		t.Fatal("cancelled queue executed")
	}
	if RequestIPadCandidateStage(0) == nil || RequestNetworkOnly(false) == nil {
		t.Fatal("settings admitted during staging reservation")
	}
	// All ordinary children attached while staging owns the reservation must
	// be cancelled before their caller can proceed into native inspection.
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ctx, cancel := context.WithCancel(context.Background())
			detach := AttachAMDSDiagnosticAttempt(cancel)
			defer detach()
			if ctx.Err() == nil {
				t.Error("new ordinary attempt escaped upgrade reservation")
			}
		}()
	}
	workers.Wait()
	release()
	release()
	if ipadUpgradeReserved.Load() {
		t.Fatal("release not idempotent")
	}
	ipadCandidateControl.Lock()
	ipadCandidateControl.busy = true
	ipadCandidateControl.Unlock()
	if _, err = reserveIPadUpgrade(); err == nil {
		t.Fatal("executing candidate cancelled for upgrade")
	}
}

func TestQueuedStopCannotCancelLaterAttempt(t *testing.T) {
	// The delayed 200ms callbacks capture a context.CancelFunc, not a lookup of
	// the then-current task. Replacing the task cannot retarget that function.
	oldCtx, stopOld := context.WithCancel(context.Background())
	newCtx, stopNew := context.WithCancel(context.Background())
	defer stopNew()
	amdsDiagnosticJob.Lock()
	original := amdsDiagnosticJob.AttemptStop
	amdsDiagnosticJob.AttemptStop = stopOld
	captured := amdsDiagnosticJob.AttemptStop
	amdsDiagnosticJob.AttemptStop = stopNew
	amdsDiagnosticJob.Unlock()
	defer func() { amdsDiagnosticJob.Lock(); amdsDiagnosticJob.AttemptStop = original; amdsDiagnosticJob.Unlock() }()
	captured()
	if oldCtx.Err() == nil || newCtx.Err() != nil {
		t.Fatal("captured queued stop targeted a replacement attempt")
	}
}

func TestOldAttemptDetachCannotClearNewOwnerStop(t *testing.T) {
	old, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	newer, cancelNew := context.WithCancel(context.Background())
	defer cancelNew()
	oldDetach := AttachAMDSDiagnosticAttempt(cancelOld)
	newDetach := AttachAMDSDiagnosticAttempt(cancelNew)
	defer newDetach()
	oldDetach()
	amdsDiagnosticJob.Lock()
	current := amdsDiagnosticJob.AttemptStop
	amdsDiagnosticJob.Unlock()
	if current == nil {
		t.Fatal("old attempt detach cleared replacement stop")
	}
	current()
	if newer.Err() == nil {
		t.Fatal("current attempt could not be stopped")
	}
	_ = old
}
