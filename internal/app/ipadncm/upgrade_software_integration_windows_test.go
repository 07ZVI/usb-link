//go:build windows && amd64

package ipadncm

import (
	"context"
	"testing"
)

// Calls only controller admission/queue code. No native device, receipt store,
// service, interface or registry operation is performed by this regression.
func TestUpgradeSoftwareReconnectRejectsExecutionAndWithdrawsOnlyIdle(t *testing.T) {
	softwareReconnectManager.Lock()
	oldState := softwareReconnectManager.state
	oldAllowed, oldQueued := softwareReconnectManager.allowed, softwareReconnectManager.queued
	oldCtx, oldCancel := softwareReconnectManager.ctx, softwareReconnectManager.cancel
	oldOff, oldOffCtx := softwareReconnectManager.offAfterJob, softwareReconnectManager.offContext
	softwareReconnectManager.state = softwareReconnectControlState{available: true, running: true}
	softwareReconnectManager.Unlock()
	oldReserved := ipadUpgradeReserved.Load()
	ipadUpgradeReserved.Store(false)
	defer func() {
		softwareReconnectManager.Lock()
		softwareReconnectManager.state = oldState
		softwareReconnectManager.allowed, softwareReconnectManager.queued = oldAllowed, oldQueued
		softwareReconnectManager.ctx, softwareReconnectManager.cancel = oldCtx, oldCancel
		softwareReconnectManager.offAfterJob, softwareReconnectManager.offContext = oldOff, oldOffCtx
		softwareReconnectManager.Unlock()
		ipadUpgradeReserved.Store(oldReserved)
	}()
	if _, err := reserveIPadUpgrade(); err == nil {
		t.Fatal("executing native job admitted for upgrade")
	}
	if RequestIPadCandidateStage(0) == nil || RequestNetworkOnly(false) == nil || HoldIPadModeDiagnostics() == nil || StartAMDSModeDiagnostic(context.Background(), "0.8.74", "running") == nil {
		t.Fatal("another iPad action escaped software execution guard")
	}
	softwareReconnectManager.Lock()
	softwareReconnectManager.state.running, softwareReconnectManager.state.recovering = false, true
	softwareReconnectManager.Unlock()
	if _, err := reserveIPadUpgrade(); err == nil {
		t.Fatal("native restoration admitted for upgrade")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	allowed := &softwareReconnectScope{}
	softwareReconnectManager.Lock()
	softwareReconnectManager.state = softwareReconnectControlState{available: true, pending: true, blocked: true, softwareAttempts: 7}
	softwareReconnectManager.allowed, softwareReconnectManager.queued = allowed, &softwareReconnectScope{}
	softwareReconnectManager.ctx, softwareReconnectManager.cancel = ctx, cancel
	softwareReconnectManager.offAfterJob, softwareReconnectManager.offContext = true, ctx
	softwareReconnectManager.Unlock()
	release, err := reserveIPadUpgrade()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if ctx.Err() == nil || IPadSoftwareReconnectBusy() || IPadSoftwareReconnectCanConnect() {
		t.Fatal("idle job not withdrawn or recovery obligation erased")
	}
	softwareReconnectManager.Lock()
	preserved := softwareReconnectManager.allowed == allowed && softwareReconnectManager.state.available && softwareReconnectManager.state.blocked && softwareReconnectManager.state.softwareAttempts == 7 && softwareReconnectManager.queued == nil
	softwareReconnectManager.Unlock()
	if !preserved {
		t.Fatal("upgrade changed consent, settings, receipt obligation or software counter")
	}
	if RunPendingIPadSoftwareReconnect(context.Background(), true) {
		t.Fatal("withdrawn native job executed")
	}
	if RequestIPadSoftwareReconnect(context.Background()) == nil || RequestIPadSoftwareReconnectSetting(context.Background(), false) == nil {
		t.Fatal("software action admitted during upgrade reservation")
	}
	release()
	if RequestNetworkOnly(false) == nil {
		t.Fatal("unresolved software restore was bypassed after release")
	}
}
