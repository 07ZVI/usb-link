//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
)

// Master registers B's atomic reservation predicate once, before serving fixed
// actions. The callback must not take controller locks or perform I/O.
func SetIPadSoftwareReconnectUpgradeGuard(held func() bool) {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	softwareReconnectManager.Lock()
	softwareReconnectManager.upgradeHeld = held
	softwareReconnectManager.Unlock()
}
func softwareReconnectUpgradeHeld() bool {
	softwareReconnectManager.Lock()
	f := softwareReconnectManager.upgradeHeld
	softwareReconnectManager.Unlock()
	return f != nil && f()
}

// Existing AMDS/candidate/network-only/hold admission sites must use this
// predicate while holding ipadActionAdmission. This file avoids modifying the
// controllers concurrently being changed by B.
func IPadSoftwareReconnectAdmissionBusy() bool { return IPadSoftwareReconnectBusy() }
func IPadSoftwareReconnectExecuting() bool {
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	return softwareReconnectManager.state.running || softwareReconnectManager.state.recovering
}

// A canceled connection callback must not revoke a fixed action already
// admitted with real consent. Explicit security failure/revocation still uses
// ClearIPadSoftwareReconnectScope, which cancels the admitted action as well.
func ForgetIdleIPadSoftwareReconnectScope(problem string) {
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	if !softwareReconnectManager.state.busy() {
		softwareReconnectManager.allowed = nil
		softwareReconnectManager.scopeCleanupVerified = false
		softwareReconnectManager.state.problem = problem
	}
}

// Caller must hold ipadActionAdmission (B's upgrade reservation transaction).
// Only an idle queued action may be withdrawn. Receipt, original values,
// blocked recovery state and actual consent survive; executing work refuses.
func CancelIdleIPadSoftwareReconnectForUpgrade() error {
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	pending := softwareReconnectManager.state.pending
	if !softwareReconnectManager.state.withdrawIdleForUpgrade() {
		return fmt.Errorf("software reconnect executing; wait for verified restoration")
	}
	if pending {
		if softwareReconnectManager.cancel != nil {
			softwareReconnectManager.cancel()
		}
		softwareReconnectManager.ctx, softwareReconnectManager.cancel, softwareReconnectManager.queued = nil, nil, nil
		softwareReconnectManager.offAfterJob, softwareReconnectManager.offContext = false, nil
	}
	return nil
}

// Separate iPad-only registration closes the enqueue/attach race without
// changing AMDS' shared controller file or touching the independent Mac.
func AttachIPadSoftwareReconnectAttempt(stop context.CancelFunc) func() {
	softwareReconnectManager.Lock()
	softwareReconnectManager.attemptEpoch++
	epoch := softwareReconnectManager.attemptEpoch
	softwareReconnectManager.attemptStop = stop
	pause := softwareReconnectManager.state.busy() || softwareReconnectManager.state.blocked
	softwareReconnectManager.Unlock()
	if pause && stop != nil {
		stop()
	}
	return func() {
		softwareReconnectManager.Lock()
		if softwareReconnectManager.attemptEpoch == epoch {
			softwareReconnectManager.attemptStop = nil
		}
		softwareReconnectManager.Unlock()
	}
}

// Exit consumes cancellation on the actual connection owner; it never waits
// on ctx.Done with an unconsumed pending flag. Original receipt restoration
// remains independent of the process cancellation context.
func FinishIPadSoftwareReconnectOwner(ctx context.Context, dir string, cleanupVerified bool) error {
	softwareReconnectManager.Lock()
	softwareReconnectManager.offAfterJob, softwareReconnectManager.offContext = false, nil
	softwareReconnectManager.Unlock()
	CancelIPadSoftwareReconnect()
	RunPendingIPadSoftwareReconnect(ctx, cleanupVerified)
	if !cleanupVerified {
		return fmt.Errorf("iPad session cleanup unresolved; software receipt retained for startup recovery")
	}
	return RecoverIPadSoftwareReconnect(dir)
}

// Cleanup proof is supplied only by main's actual connection owner. It cannot
// establish consent: a retained real grant must already exist. This permits a
// native handle/configuration refresh after legitimate verified restoration.
func MarkIPadSoftwareReconnectSessionCleanup(verified bool) {
	softwareReconnectManager.Lock()
	softwareReconnectManager.scopeCleanupVerified = verified && softwareReconnectManager.allowed != nil
	if !verified {
		softwareReconnectManager.allowed = nil
		if c := softwareReconnectManager.cancel; c != nil {
			c()
		}
	}
	softwareReconnectManager.Unlock()
}
