package ipadncm

import "testing"

func TestSoftwareControllerUnavailableDoesNotBlockLegacyOrAcceptRequests(t *testing.T) {
	var s softwareReconnectControlState
	if s.busy() || !s.canConnect() || s.queue() {
		t.Fatal("default changed legacy connection", s)
	}
	s.available = true
	if !s.queue() || s.canConnect() || !s.busy() || s.queue() {
		t.Fatal("queued action did not exclusively pause ordinary iPad", s)
	}
	if !s.begin() || s.begin() || s.canConnect() {
		t.Fatal("job executed more than once or released pause", s)
	}
}
func TestSoftwareControllerCancellationNeverMeansSuccessfulReconnect(t *testing.T) {
	s := softwareReconnectControlState{available: true}
	s.queue()
	s.begin()
	s.finish(softwareReconnectDraftResult{SoftwareAttempt: true, DisabledVerified: true, RestoredVerified: true}, "context canceled", true, false)
	if s.phase != "canceled_no_unverified_root_changes" || s.softwareAttempts != 1 || !s.canConnect() {
		t.Fatal(s)
	}
	s.queue()
	s.begin()
	s.finish(softwareReconnectDraftResult{}, "canceled before mutation", true, false)
	if s.softwareAttempts != 1 || s.phase == "cm_root_restored_network_not_yet_verified" {
		t.Fatal("pre-canceled action counted as physical/success", s)
	}
}
func TestSoftwareControllerFailedJournalCommitAndRecoveryBlockConnection(t *testing.T) {
	for _, r := range []softwareReconnectDraftResult{{}, {SoftwareAttempt: true, RecoveryPending: true}, {SoftwareAttempt: true, RestoredVerified: true}} {
		s := softwareReconnectControlState{available: true}
		s.queue()
		s.begin()
		s.finish(r, "receipt or restore failed", false, true)
		if s.canConnect() || s.queue() || s.phase != "recovery_required_receipt_retained" {
			t.Fatal("failed/ambiguous durable state released connection", s)
		}
	}
}
func TestSoftwareControllerSuccessProvesCMOnly(t *testing.T) {
	s := softwareReconnectControlState{available: true}
	s.queue()
	s.begin()
	s.finish(softwareReconnectDraftResult{SoftwareAttempt: true, DisabledVerified: true, RestoredVerified: true}, "", false, false)
	if !s.canConnect() || s.phase != "cm_root_restored_network_not_yet_verified" || s.softwareAttempts != 1 {
		t.Fatal("CM success misreported as network/physical proof", s)
	}
}

func TestSoftwareSettingsOffRetainsUnresolvedReceiptAcrossCancel(t *testing.T) {
	s := softwareReconnectControlState{available: true, blocked: true}
	if s.queueSetting(true) {
		t.Fatal("ON bypassed unresolved receipt")
	}
	if !s.queueSetting(false) || s.canConnect() || !s.begin() {
		t.Fatal("OFF could not queue verified recovery", s)
	}
	s.finish(softwareReconnectDraftResult{}, "canceled before recovery", true, true)
	if !s.blocked || s.canConnect() || s.queueSetting(true) {
		t.Fatal("canceled OFF erased original recovery obligation", s)
	}
}

func TestSoftwareSettingsDefaultOffCanQueueButCannotExecuteTwice(t *testing.T) {
	var s softwareReconnectControlState
	if !s.queueSetting(true) || s.available || s.queueSetting(false) || !s.begin() || s.begin() {
		t.Fatal("setting admission prematurely enabled or executed twice", s)
	}
	s.finish(softwareReconnectDraftResult{}, "", false, false)
	if s.available || s.softwareAttempts != 0 || !s.canConnect() {
		t.Fatal("pure setting consumed as hardware/physical proof", s)
	}
}

func TestUpgradeWithdrawsOnlyIdleSoftwareIntentAndRetainsRecoveryObligation(t *testing.T) {
	s := softwareReconnectControlState{pending: true, blocked: true, softwareAttempts: 2}
	if !s.withdrawIdleForUpgrade() || s.pending || !s.blocked || s.softwareAttempts != 2 || s.canConnect() {
		t.Fatal("withdrawal lost previous receipt obligation", s)
	}
	for _, active := range []softwareReconnectControlState{{running: true}, {recovering: true}, {pending: true, running: true}} {
		before := active
		if active.withdrawIdleForUpgrade() || active != before {
			t.Fatal("upgrade withdrew executing native work", before, active)
		}
	}
}
