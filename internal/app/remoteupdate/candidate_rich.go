package remoteupdate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
)

const CandidateRichByteLimit = 64 << 10

// CandidateRichObservation is a diagnostic snapshot from an actual bound child.
// It is never a process, path, network, cleanup or readiness authorization.
type CandidateCleanupFailure struct {
	Phase            string `json:"phase"`
	Code             string `json:"code"`
	CleanupConfirmed bool   `json:"cleanup_confirmed"`
}

func CandidateCleanupFailureValid(v *CandidateCleanupFailure) bool {
	if v == nil || v.Phase != "parent_recover" || v.CleanupConfirmed {
		return false
	}
	switch v.Code {
	case "MAC_RUNTIME_OWNERSHIP_UNAVAILABLE", "MAC_RECOVERY_RECORD_INVALID", "MAC_BRIDGE_STILL_RUNNING", "MAC_BRIDGE_LOCK_UNAVAILABLE", "MAC_PERSISTENT_RECOVERY_UNPROVEN", "MAC_DAD_RECOVERY_ORIGINAL_UNPROVEN", "MAC_DAD_RECOVERY_WITHOUT_FACTORY_ORIGINAL_PENDING", "MAC_PERSISTENT_COMPLETED_SESSION_UNPROVEN", "MAC_PERSISTENT_SESSION_CLEANUP_UNPROVEN", "MAC_PERSISTENT_RECOVERY_STORE_UNREADABLE", "MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN", "MAC_ADAPTER_RECOVERY_UNCONFIRMED", "MAC_RECOVERY_JOURNAL_NOT_CLEARED", "MAC_CLEANUP_ERROR_UNCLASSIFIED":
		return true
	}
	return false
}

type CandidateRichObservation struct {
	BridgePID        uint32                               `json:"bridge_pid"`
	BridgeCreation   uint64                               `json:"bridge_creation_filetime"`
	BridgeSHA256     string                               `json:"bridge_sha256"`
	Failure          netconfig.NativeStepDiagnostic       `json:"failure"`
	NullProjection   *netconfig.MacNullProjection         `json:"null_projection,omitempty"`
	AnchorProjection *netconfig.MacAnchorProjection       `json:"anchor_projection,omitempty"`
	DiagnosticTiming *netconfig.BridgeNetworkScriptTiming `json:"diagnostic_timing,omitempty"`
	CleanupFailure   *CandidateCleanupFailure             `json:"cleanup_failure,omitempty"`
}
type CandidateRichReceipt struct {
	Schema int `json:"schema"`
	CandidateIdentity
	ObservedUnixNano int64                    `json:"observed_unix_nano"`
	Observation      CandidateRichObservation `json:"observation"`
}

func CandidateRichObservationValid(v *CandidateRichObservation) bool {
	if v == nil || v.BridgePID == 0 || v.BridgeCreation == 0 || len(v.BridgeSHA256) != 64 || strings.Trim(v.BridgeSHA256, "0123456789abcdef") != "" || !netconfig.NativeStepDiagnosticValid(v.Failure) {
		return false
	}
	if v.CleanupFailure != nil && !CandidateCleanupFailureValid(v.CleanupFailure) {
		return false
	}
	if v.NullProjection != nil && (v.Failure.Operation != "mac_resident_mac_plan" || v.Failure.CauseCode != "USB_NATIVE_FIREWALL_CONSTRAINT_NULL" || !netconfig.MacNullProjectionValid(v.NullProjection)) {
		return false
	}
	if v.AnchorProjection != nil && (v.Failure.Operation != "mac_resident_mac_plan" || v.Failure.CauseCode != "USB_RESIDENT_FOREIGN_SCOPE" || !netconfig.MacAnchorProjectionValid(v.AnchorProjection)) {
		return false
	}
	if v.DiagnosticTiming != nil && (v.Failure.Operation != "mac_resident_mac_plan" || (v.Failure.CauseCode != "USB_NATIVE_FIREWALL_CONSTRAINT_NULL" && v.Failure.CauseCode != "USB_RESIDENT_FOREIGN_SCOPE") || v.DiagnosticTiming.Operation != "diagnostic" || len(netconfig.CopyBridgeNetworkScriptTimings([]netconfig.BridgeNetworkScriptTiming{*v.DiagnosticTiming})) != 1) {
		return false
	}
	return true
}
func CopyCandidateRichObservation(v *CandidateRichObservation) *CandidateRichObservation {
	if !CandidateRichObservationValid(v) {
		return nil
	}
	out := *v
	if v.CleanupFailure != nil {
		secondary := *v.CleanupFailure
		out.CleanupFailure = &secondary
	}
	out.NullProjection = netconfig.CopyMacNullProjection(v.NullProjection)
	out.AnchorProjection = netconfig.CopyMacAnchorProjection(v.AnchorProjection)
	if v.DiagnosticTiming != nil {
		row := *v.DiagnosticTiming
		out.DiagnosticTiming = &row
	}
	return &out
}

// Historical matching deliberately has no liveness or cross-machine wall clock
// predicate. Identity is the recorded signed job's exact candidate, not the
// process currently serving status. Capture admission belongs to the writer.
func CandidateRichMatches(v CandidateRichReceipt, expected CandidateIdentity) bool {
	return v.Schema == 1 && candidateIdentityValid(expected) && v.CandidateIdentity == expected && v.ObservedUnixNano > 0 && v.Observation.BridgePID != expected.PID && CandidateRichObservationValid(&v.Observation)
}

// Enrichment may add a projection/timing to the SAME first failure and bound
// child. New attempts and later cleanup failures never replace that first cause.
func MergeCandidateRich(old, next CandidateRichReceipt) (CandidateRichReceipt, error) {
	bad := errors.New("candidate rich first failure changed")
	if !CandidateRichMatches(next, next.CandidateIdentity) {
		return CandidateRichReceipt{}, bad
	}
	if reflect.DeepEqual(old, CandidateRichReceipt{}) {
		next.Observation = *CopyCandidateRichObservation(&next.Observation)
		return next, nil
	}
	if !CandidateRichMatches(old, next.CandidateIdentity) || next.ObservedUnixNano < old.ObservedUnixNano || old.Observation.BridgePID != next.Observation.BridgePID || old.Observation.BridgeCreation != next.Observation.BridgeCreation || old.Observation.BridgeSHA256 != next.Observation.BridgeSHA256 || old.Observation.Failure != next.Observation.Failure {
		return CandidateRichReceipt{}, bad
	}
	out := next
	out.Observation = *CopyCandidateRichObservation(&next.Observation)
	if old.Observation.NullProjection != nil {
		if next.Observation.NullProjection != nil && !reflect.DeepEqual(old.Observation.NullProjection, next.Observation.NullProjection) {
			return CandidateRichReceipt{}, bad
		}
		out.Observation.NullProjection = netconfig.CopyMacNullProjection(old.Observation.NullProjection)
	}
	if old.Observation.AnchorProjection != nil {
		if next.Observation.AnchorProjection != nil && !reflect.DeepEqual(old.Observation.AnchorProjection, next.Observation.AnchorProjection) {
			return CandidateRichReceipt{}, bad
		}
		out.Observation.AnchorProjection = netconfig.CopyMacAnchorProjection(old.Observation.AnchorProjection)
	}
	if old.Observation.DiagnosticTiming != nil {
		if next.Observation.DiagnosticTiming != nil && *old.Observation.DiagnosticTiming != *next.Observation.DiagnosticTiming {
			return CandidateRichReceipt{}, bad
		}
		row := *old.Observation.DiagnosticTiming
		out.Observation.DiagnosticTiming = &row
	}
	if old.Observation.CleanupFailure != nil {
		if next.Observation.CleanupFailure != nil && *old.Observation.CleanupFailure != *next.Observation.CleanupFailure {
			return CandidateRichReceipt{}, bad
		}
		secondary := *old.Observation.CleanupFailure
		out.Observation.CleanupFailure = &secondary
	}
	return out, nil
}
func DecodeCandidateRich(data []byte) (CandidateRichReceipt, error) {
	var out CandidateRichReceipt
	bad := errors.New("candidate rich schema rejected")
	if len(data) == 0 || len(data) > CandidateRichByteLimit {
		return out, bad
	}
	d := json.NewDecoder(bytes.NewReader(data))
	fields, e := candidateObject(d, map[string]bool{"schema": true, "job_id": true, "version": true, "sha256": true, "pid": true, "creation_filetime": true, "observed_unix_nano": true, "observation": true})
	if e != nil || len(fields) != 8 || d.Decode(new(any)) != io.EOF {
		return out, bad
	}
	for _, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return out, bad
		}
	}
	d = json.NewDecoder(bytes.NewReader(fields["observation"]))
	obs, e := candidateObject(d, map[string]bool{"bridge_pid": true, "bridge_creation_filetime": true, "bridge_sha256": true, "failure": true, "null_projection": true, "anchor_projection": true, "diagnostic_timing": true, "cleanup_failure": true})
	if e != nil || d.Decode(new(any)) != io.EOF {
		return out, bad
	}
	for _, key := range []string{"bridge_pid", "bridge_creation_filetime", "bridge_sha256", "failure"} {
		if obs[key] == nil {
			return out, bad
		}
	}
	for _, raw := range obs {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return out, bad
		}
	}
	if _, e = netconfig.DecodeNativeStepFailureMessage(obs["failure"]); e != nil {
		return out, bad
	}
	if raw := obs["null_projection"]; raw != nil {
		if _, e = netconfig.DecodeMacNullProjection(raw); e != nil {
			return out, bad
		}
	}
	if raw := obs["anchor_projection"]; raw != nil {
		if _, e = netconfig.DecodeMacAnchorProjection(raw); e != nil {
			return out, bad
		}
	}
	if raw := obs["diagnostic_timing"]; raw != nil {
		if _, e = netconfig.DecodeBridgeNetworkScriptTiming(raw); e != nil {
			return out, bad
		}
	}
	if raw := obs["cleanup_failure"]; raw != nil {
		nested := json.NewDecoder(bytes.NewReader(raw))
		fields, e := candidateObject(nested, map[string]bool{"phase": true, "code": true, "cleanup_confirmed": true})
		if e != nil || len(fields) != 3 || nested.Decode(new(any)) != io.EOF {
			return out, bad
		}
		for _, field := range fields {
			if bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
				return out, bad
			}
		}
	}
	if json.Unmarshal(data, &out) != nil || !CandidateRichMatches(out, out.CandidateIdentity) {
		return CandidateRichReceipt{}, bad
	}
	return out, nil
}
