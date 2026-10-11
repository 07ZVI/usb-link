package macconnection

import (
	"encoding/json"
	"errors"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"testing"
)

func TestMacFailedStartupSnapshotRequiresVerifiedSourceAndCurrentAttempt(t *testing.T) {
	epoch := beginNativeFailureAttempt()
	defer beginNativeFailureAttempt()
	b := nativeChildBinding{pid: 17, creation: 29, nonce: strings.Repeat("a", 24)}
	f := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_resident_mac_plan", Code: "MAC_RESIDENT_MAC_PLAN_FAILED", CauseCode: "USB_RESIDENT_FOREIGN_SCOPE"}
	if FailedStartupDiagnosticSnapshot() != nil || bindNativeFailureChildSource(epoch, b, strings.Repeat("0", 64)) {
		t.Fatal("unproven source accepted")
	}
	if !bindNativeFailureChild(epoch, b) || !recordNativeFailure(epoch, b, f) || FailedStartupDiagnosticSnapshot() != nil {
		t.Fatal("source-free legacy capture published as rich evidence")
	}
	if bindNativeFailureChildSource(epoch, b, expectedBridgeSHA) {
		t.Fatal("source identity added retrospectively to an already bound attempt")
	}
	epoch = beginNativeFailureAttempt()
	if !bindNativeFailureChildSource(epoch, b, expectedBridgeSHA) || FailedStartupDiagnosticSnapshot() != nil || !recordNativeFailure(epoch, b, f) {
		t.Fatal("verified source binding rejected")
	}
	v := FailedStartupDiagnosticSnapshot()
	if v == nil || v.BridgePID != b.pid || v.BridgeCreation != b.creation || v.BridgeSHA256 != expectedBridgeSHA || v.Failure != f {
		t.Fatal("actual attempt identity or first failure missing", v)
	}
	foreign := b
	foreign.creation++
	if bindNativeFailureChildSource(epoch, foreign, expectedBridgeSHA) {
		t.Fatal("bound child identity replaced")
	}
	clearNativeFailure(epoch)
	if FailedStartupDiagnosticSnapshot() != nil {
		t.Fatal("successful readiness did not clear failed snapshot")
	}
	if !recordNativeFailure(epoch, b, f) {
		t.Fatal("current first failure lost")
	}
	next := beginNativeFailureAttempt()
	if recordMacCleanupFailure(epoch, b, errors.New("MAC_ADAPTER_RECOVERY_UNCONFIRMED")) || FailedStartupDiagnosticSnapshot() != nil {
		t.Fatal("old attempt retained or enriched in new epoch")
	}
	if !bindNativeFailureChildSource(next, b, expectedBridgeSHA) || !recordNativeFailure(next, b, f) {
		t.Fatal("new verified attempt rejected")
	}
}

func TestMacFailedStartupSnapshotDeepCopiesActualDiagnosticAndSecondaryCleanup(t *testing.T) {
	epoch := beginNativeFailureAttempt()
	defer beginNativeFailureAttempt()
	b := nativeChildBinding{pid: 17, creation: 29, nonce: strings.Repeat("a", 24)}
	f := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_resident_mac_plan", Code: "MAC_RESIDENT_MAC_PLAN_FAILED", CauseCode: "USB_RESIDENT_FOREIGN_SCOPE", CauseField: "MSFT_NetProtocolPortFilter/IcmpType"}
	if !bindNativeFailureChildSource(epoch, b, expectedBridgeSHA) || !recordNativeFailure(epoch, b, f) {
		t.Fatal("bind failed")
	}
	a, _ := anchorProjectionFixture(t)
	row := netconfig.BridgeNetworkScriptTiming{Operation: "diagnostic", Count: 1, DurationMS: 35000, Success: true}
	if !recordMacAnchorProjection(epoch, b, a) || !recordMacDiagnosticTiming(epoch, b, row) {
		t.Fatal("actual projection/timing rejected")
	}
	foreign := b
	foreign.creation++
	if recordMacCleanupFailure(epoch, foreign, errors.New("MAC_BRIDGE_STILL_RUNNING")) || recordMacCleanupFailure(epoch, b, nil) {
		t.Fatal("foreign child or successful cleanup misclassified")
	}
	if !recordMacCleanupFailure(epoch, b, errors.New("MAC_ADAPTER_RECOVERY_UNCONFIRMED: C:\\secret\\file")) || recordMacCleanupFailure(epoch, b, errors.New("MAC_BRIDGE_STILL_RUNNING")) {
		t.Fatal("actual secondary missing or overwritten")
	}
	v := FailedStartupDiagnosticSnapshot()
	if v == nil || v.Failure != f || v.CleanupFailure == nil || v.CleanupFailure.CleanupConfirmed || v.CleanupFailure.Phase != "parent_recover" || v.CleanupFailure.Code != "MAC_ADAPTER_RECOVERY_UNCONFIRMED" || v.DiagnosticTiming == nil || *v.DiagnosticTiming != row || !netconfig.MacAnchorProjectionValid(v.AnchorProjection) {
		t.Fatal("first/secondary diagnostics not independently retained", v)
	}
	v.AnchorProjection.Rows[0].Fields[0].Field = "invalid"
	v.DiagnosticTiming.DurationMS = -1
	v.CleanupFailure.Code = "invalid"
	v.Failure.Operation = "invalid"
	v.BridgeSHA256 = "invalid"
	next := FailedStartupDiagnosticSnapshot()
	if next == nil || next.Failure != f || !netconfig.MacAnchorProjectionValid(next.AnchorProjection) || *next.DiagnosticTiming != row || next.CleanupFailure.Code != "MAC_ADAPTER_RECOVERY_UNCONFIRMED" || next.BridgeSHA256 != expectedBridgeSHA {
		t.Fatal("caller mutated retained diagnostic")
	}
	if got := NativeStartupFailureDetails()["cleanup_failure"]; got != *next.CleanupFailure {
		t.Fatal("maintenance details lost actual secondary", got)
	}
	j, err := json.Marshal(next)
	if err != nil || strings.Contains(string(j), "secret") || strings.Contains(string(j), b.nonce) {
		t.Fatal("raw error or nonce escaped bounded snapshot", string(j), err)
	}
}

func TestMacFailedStartupSnapshotDeepCopiesNullProjection(t *testing.T) {
	epoch := beginNativeFailureAttempt()
	defer beginNativeFailureAttempt()
	b := nativeChildBinding{pid: 19, creation: 31, nonce: strings.Repeat("b", 24)}
	f := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_resident_mac_plan", Code: "MAC_RESIDENT_MAC_PLAN_FAILED", CauseCode: "USB_NATIVE_FIREWALL_CONSTRAINT_NULL"}
	bindNativeFailureChildSource(epoch, b, expectedBridgeSHA)
	recordNativeFailure(epoch, b, f)
	if !recordMacNullProjection(epoch, b, nullProjectionFixture()) {
		t.Fatal("actual null diagnostic rejected")
	}
	v := FailedStartupDiagnosticSnapshot()
	if v == nil || !netconfig.MacNullProjectionValid(v.NullProjection) || v.AnchorProjection != nil || v.CleanupFailure != nil {
		t.Fatal("unobserved diagnostics fabricated")
	}
	v.NullProjection.Rows[0].Status = "invalid"
	if !netconfig.MacNullProjectionValid(FailedStartupDiagnosticSnapshot().NullProjection) {
		t.Fatal("null snapshot aliases retained rows")
	}
}

func TestMacCleanupFailureClassificationDoesNotExtractRawEmbeddedMarkers(t *testing.T) {
	if macRecoveryFailureCode(nil) != "" {
		t.Fatal("nil classified as failure")
	}
	for _, code := range []string{"MAC_BRIDGE_STILL_RUNNING", "MAC_BRIDGE_LOCK_UNAVAILABLE", "MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN", "MAC_RECOVERY_JOURNAL_NOT_CLEARED", "MAC_PERSISTENT_SESSION_CLEANUP_UNPROVEN"} {
		if got := macRecoveryFailureCode(errors.New(code + ": arbitrary provider error")); got != code {
			t.Fatal("compiled recovery classification lost", got)
		}
	}
	for _, raw := range []string{"prefix MAC_BRIDGE_STILL_RUNNING", "MAC_BRIDGE_STILL_RUNNING_EXTRA", " MAC_BRIDGE_STILL_RUNNING", "unknown: MAC_BRIDGE_STILL_RUNNING", "MAC_BRIDGE_STILL_RUNNING=secret"} {
		if got := macRecoveryFailureCode(errors.New(raw)); got != "MAC_CLEANUP_ERROR_UNCLASSIFIED" {
			t.Fatal("embedded/error content promoted to classification", raw, got)
		}
	}
}

func TestMacCleanupFailureObservationRequiresExactFiniteFields(t *testing.T) {
	valid := MacCleanupFailureObservation{Phase: "parent_recover", Code: "MAC_BRIDGE_STILL_RUNNING", CleanupConfirmed: false}
	if !MacCleanupFailureObservationValid(&valid) || MacCleanupFailureObservationValid(nil) {
		t.Fatal("valid/nil cleanup observation mishandled")
	}
	for _, invalid := range []MacCleanupFailureObservation{
		{Phase: "child_exit", Code: valid.Code},
		{Phase: valid.Phase, Code: "unknown"},
		{Phase: valid.Phase, Code: valid.Code + ": raw"},
		{Phase: valid.Phase, Code: valid.Code, CleanupConfirmed: true},
	} {
		if MacCleanupFailureObservationValid(&invalid) {
			t.Fatal("invented or nonfinite cleanup observation accepted", invalid)
		}
	}
}
