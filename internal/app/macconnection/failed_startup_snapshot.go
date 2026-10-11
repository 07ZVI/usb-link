package macconnection

import (
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
)

// FailedStartupDiagnosticObservation is a bounded historical observation of
// this attempt's verified child source and first failure. Its capture does not
// establish current process liveness, readiness or cleanup authorization.
// Neither the private stop nonce nor any path or raw error leaves this DTO.
type FailedStartupDiagnosticObservation struct {
	BridgePID        uint32
	BridgeCreation   uint64
	BridgeSHA256     string
	Failure          netconfig.NativeStepDiagnostic
	NullProjection   *netconfig.MacNullProjection
	AnchorProjection *netconfig.MacAnchorProjection
	DiagnosticTiming *netconfig.BridgeNetworkScriptTiming
	CleanupFailure   *MacCleanupFailureObservation
}

// MacCleanupFailureObservation records only an actual failed parent recovery,
// separately from the child first failure. It does not claim a process exit
// code, nor that the later parent cancellation has already occurred.
type MacCleanupFailureObservation struct {
	Phase            string `json:"phase"`
	Code             string `json:"code"`
	CleanupConfirmed bool   `json:"cleanup_confirmed"`
}

func MacCleanupFailureObservationValid(v *MacCleanupFailureObservation) bool {
	return v != nil && v.Phase == "parent_recover" && !v.CleanupConfirmed && macRecoveryFailureCodeValid(v.Code)
}

func compiledBridgeHash(hash string) bool {
	return len(hash) == 64 && strings.Trim(hash, "0123456789abcdef") == "" && hash == expectedBridgeSHA
}

// FailedStartupDiagnosticSnapshot returns a safe independent copy, or nil
// until the current epoch has both an actual captured source-bound launch and
// a valid first failure. A new attempt and successful readiness invalidate it.
func FailedStartupDiagnosticSnapshot() *FailedStartupDiagnosticObservation {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	s := &macNativeFailure
	if s.binding.pid == 0 || s.binding.creation == 0 || !compiledBridgeHash(s.bridgeSHA256) || !netconfig.NativeStepDiagnosticValid(s.failure) {
		return nil
	}
	v := &FailedStartupDiagnosticObservation{
		BridgePID: s.binding.pid, BridgeCreation: s.binding.creation, BridgeSHA256: s.bridgeSHA256,
		Failure:          s.failure,
		NullProjection:   netconfig.CopyMacNullProjection(s.projection),
		AnchorProjection: netconfig.CopyMacAnchorProjection(s.anchorProjection),
	}
	if s.diagnosticTiming != nil && len(netconfig.CopyBridgeNetworkScriptTimings([]netconfig.BridgeNetworkScriptTiming{*s.diagnosticTiming})) == 1 && s.diagnosticTiming.Operation == "diagnostic" {
		row := *s.diagnosticTiming
		v.DiagnosticTiming = &row
	}
	if MacCleanupFailureObservationValid(s.cleanupFailure) {
		row := *s.cleanupFailure
		v.CleanupFailure = &row
	}
	return v
}

// Called at the actual Recover error boundary after the child reader drained.
// The historical source identity is retained even after that child has exited.
func recordMacCleanupFailure(epoch uint64, b nativeChildBinding, err error) bool {
	if err == nil {
		return false
	}
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	s := &macNativeFailure
	if epoch != s.epoch || b.pid == 0 || s.binding != b || !compiledBridgeHash(s.bridgeSHA256) || !netconfig.NativeStepDiagnosticValid(s.failure) || s.cleanupFailure != nil {
		return false
	}
	s.cleanupFailure = &MacCleanupFailureObservation{Phase: "parent_recover", Code: macRecoveryFailureCode(err), CleanupConfirmed: false}
	return true
}

// Only the compiled outer classification is retained. Unknown recovery errors
// remain explicitly unclassified; embedded marker text is never extracted.
func macRecoveryFailureCode(err error) string {
	if err == nil {
		return ""
	}
	code, _, _ := strings.Cut(err.Error(), ":")
	if macRecoveryFailureCodeValid(code) && code != "MAC_CLEANUP_ERROR_UNCLASSIFIED" {
		return code
	}
	return "MAC_CLEANUP_ERROR_UNCLASSIFIED"
}

func macRecoveryFailureCodeValid(code string) bool {
	switch code {
	case "MAC_RUNTIME_OWNERSHIP_UNAVAILABLE", "MAC_RECOVERY_RECORD_INVALID",
		"MAC_BRIDGE_STILL_RUNNING", "MAC_BRIDGE_LOCK_UNAVAILABLE",
		"MAC_PERSISTENT_RECOVERY_UNPROVEN", "MAC_DAD_RECOVERY_ORIGINAL_UNPROVEN",
		"MAC_DAD_RECOVERY_WITHOUT_FACTORY_ORIGINAL_PENDING", "MAC_PERSISTENT_COMPLETED_SESSION_UNPROVEN",
		"MAC_PERSISTENT_SESSION_CLEANUP_UNPROVEN", "MAC_PERSISTENT_RECOVERY_STORE_UNREADABLE",
		"MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN", "MAC_ADAPTER_RECOVERY_UNCONFIRMED",
		"MAC_RECOVERY_JOURNAL_NOT_CLEARED", "MAC_CLEANUP_ERROR_UNCLASSIFIED":
		return true
	default:
		return false
	}
}
