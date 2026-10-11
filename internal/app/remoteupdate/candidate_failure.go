package remoteupdate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"time"
)

// Diagnostic-only fixed fields. These records never acknowledge readiness,
// authorize a process, select a path, or relax guarded rollback ownership.
type CandidateIdentity struct {
	JobID    string `json:"job_id"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
	PID      uint32 `json:"pid"`
	Creation uint64 `json:"creation_filetime"`
}
type CandidateStartupObservation struct {
	Phase           string `json:"phase"`
	Code            string `json:"code"`
	NativeError     uint32 `json:"native_error,omitempty"`
	NativeOperation string `json:"native_operation,omitempty"`
	NativeHRESULT   uint32 `json:"native_hresult,omitempty"`
}
type CandidateStatusReceipt struct {
	Schema int `json:"schema"`
	CandidateIdentity
	ObservedUnixNano int64                       `json:"observed_unix_nano"`
	Observation      CandidateStartupObservation `json:"observation"`
}
type CandidateFailure struct {
	CandidateIdentity
	Reason           string `json:"reason"`
	Phase            string `json:"phase"`
	Code             string `json:"code"`
	NativeError      uint32 `json:"native_error,omitempty"`
	NativeOperation  string `json:"native_operation,omitempty"`
	NativeHRESULT    uint32 `json:"native_hresult,omitempty"`
	ReceiptObserved  bool   `json:"receipt_observed"`
	ObservedUnixNano int64  `json:"observed_unix_nano,omitempty"`
}

func candidateIdentityValid(v CandidateIdentity) bool {
	id, e := hex.DecodeString(v.JobID)
	hash, he := hex.DecodeString(v.SHA256)
	_, ve := version(v.Version)
	return e == nil && len(id) == 16 && len(v.JobID) == 32 && he == nil && len(hash) == 32 && len(v.SHA256) == 64 && ve == nil && v.PID != 0 && v.Creation != 0
}
func SanitizeCandidateStartup(v CandidateStartupObservation) CandidateStartupObservation {
	switch v.Phase {
	case "preparation", "cleanup", "exit_cleanup", "health":
	default:
		v.Phase = "unavailable"
	}
	// Keep a finite compiled vocabulary; unregistered provider errors are unknown,
	// never raw COM text, account names, paths, device instances or arbitrary logs.
	switch v.Code {
	case "USB_HOST_SOURCE_PIN_FAILED", "USB_HOST_RESIDENT_PREPARE_FAILED", "USB_HOST_RESIDENT_BATCH_FAILED", "USB_HOST_SOURCE_COMPLETE_FAILED", "USB_HOST_NATIVE_STEP_FAILED", "USB_HOST_CLOSE_COMPLETION_PENDING", "USB_HOST_CLOSE_MAPPING_UNPROVEN", "USB_HOST_CLOSE_NODE_CHANGED", "USB_HOST_CLOSE_JOURNAL_CHANGED", "USB_HOST_CLOSE_ADDRESS_OWNERSHIP_UNPROVEN", "USB_HOST_CLOSE_ADDRESS_NOT_ABSENT", "USB_HOST_NATIVE_PNP_BINDING_NOT_UNIQUE", "USB_HOST_NATIVE_NODE_STATE_UNPROVEN", "USB_HOST_NATIVE_OPERATION_FAILED", "USB_HOST_OPERATION_FAILED", "USB_HOST_PREPARED_HEALTH_UNCONFIRMED", "USB_HOST_DRIVER_READBACK_UNCONFIRMED", "USB_HOST_PREPARATION_RETRYING", "USB_HOST_REMOVAL_REBOOT_UNPROVEN", "USB_HOST_RECREATE_ATTEMPT_PENDING", "USB_HOST_RECREATE_TRANSACTION_CHANGED", "USB_HOST_RECREATE_FLAGS_UNPROVEN", "USB_HOST_INTERFACE_CHANGED", "USB_HOST_ADDRESS_OWNERSHIP_CHANGED", "USB_HOST_ADAPTER_ABSENCE_UNCONFIRMED":
	default:
		v.Code = "CANDIDATE_FAILURE_UNAVAILABLE"
		v.NativeError = 0
	}
	if !netconfig.NativeOperationValid(v.NativeOperation) || (v.Code != "USB_HOST_NATIVE_OPERATION_FAILED" && v.Code != "USB_HOST_NATIVE_STEP_FAILED") {
		v.NativeOperation = ""
		v.NativeHRESULT = 0
	}
	if v.NativeOperation == "" || int32(v.NativeHRESULT) >= 0 {
		v.NativeHRESULT = 0
	}
	if v.Code != "USB_HOST_NATIVE_OPERATION_FAILED" {
		v.NativeError = 0
	}
	return v
}
func CandidateStatusMatches(r CandidateStatusReceipt, expected CandidateIdentity, now time.Time) bool {
	age := now.Sub(time.Unix(0, r.ObservedUnixNano))
	return r.Schema == 1 && candidateIdentityValid(expected) && r.CandidateIdentity == expected && r.ObservedUnixNano > 0 && age >= 0 && age <= 10*time.Second && r.Observation == SanitizeCandidateStartup(r.Observation)
}
func CandidateFailureReasonValid(s string) bool {
	switch s {
	case "EXIT_BEFORE_HEALTH", "HEALTH_TIMEOUT", "OWNED_LOGIN_ENTRIES_FAILED", "CORE_INSTALL_FAILED", "CANDIDATE_LAUNCH_FAILED":
		return true
	}
	return false
}
func RecordCandidateFailure(expected CandidateIdentity, reason string, receipt CandidateStatusReceipt, now time.Time) CandidateFailure {
	if !CandidateFailureReasonValid(reason) {
		return CandidateFailure{}
	}
	v := CandidateFailure{CandidateIdentity: expected, Reason: reason, Phase: "unavailable", Code: "CANDIDATE_FAILURE_UNAVAILABLE"}
	if CandidateStatusMatches(receipt, expected, now) {
		v.Phase = receipt.Observation.Phase
		v.Code = receipt.Observation.Code
		v.NativeError = receipt.Observation.NativeError
		v.NativeOperation = receipt.Observation.NativeOperation
		v.NativeHRESULT = receipt.Observation.NativeHRESULT
		v.ReceiptObserved = true
		v.ObservedUnixNano = receipt.ObservedUnixNano
	}
	return v
}
func CandidateFailureDisplay(v CandidateFailure, expected CandidateIdentity) map[string]string {
	out := map[string]string{}
	if !CandidateFailureReasonValid(v.Reason) || v.CandidateIdentity != expected || !candidateEnvelopeValid(expected) {
		return out
	}
	normalized := SanitizeCandidateStartup(CandidateStartupObservation{Phase: v.Phase, Code: v.Code, NativeError: v.NativeError, NativeOperation: v.NativeOperation, NativeHRESULT: v.NativeHRESULT})
	if normalized.Phase != v.Phase || normalized.Code != v.Code || normalized.NativeError != v.NativeError || normalized.NativeOperation != v.NativeOperation || normalized.NativeHRESULT != v.NativeHRESULT {
		return out
	}
	if v.ReceiptObserved {
		if !candidateIdentityValid(expected) || v.ObservedUnixNano <= 0 {
			return out
		}
	} else if v.Phase != "unavailable" || v.Code != "CANDIDATE_FAILURE_UNAVAILABLE" || v.NativeError != 0 || v.NativeOperation != "" || v.NativeHRESULT != 0 || v.ObservedUnixNano != 0 {
		return out
	}
	out["candidate_failure_reason"] = v.Reason
	out["candidate_failure_phase"] = v.Phase
	out["candidate_failure_code"] = v.Code
	if v.NativeOperation != "" {
		out["candidate_failure_operation"] = v.NativeOperation
	}
	if v.ReceiptObserved && candidateIdentityValid(expected) {
		out["candidate_failure_receipt_observed"] = "true"
	} else {
		out["candidate_failure_receipt_observed"] = "false"
	}
	return out
}

// The schema is fixed, bounded and duplicate-free, including embedded identity
// fields. A malformed observation never becomes a candidate failure cause.
func DecodeCandidateStatus(data []byte) (CandidateStatusReceipt, error) {
	var out CandidateStatusReceipt
	if len(data) == 0 || len(data) > 4096 {
		return out, fmt.Errorf("candidate status size rejected")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	fields, err := candidateObject(d, map[string]bool{"schema": true, "job_id": true, "version": true, "sha256": true, "pid": true, "creation_filetime": true, "observed_unix_nano": true, "observation": true})
	if err != nil {
		return out, err
	}
	if len(fields) != 8 {
		return out, fmt.Errorf("candidate status missing field")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return out, fmt.Errorf("candidate status trailing data")
	}
	nested := json.NewDecoder(bytes.NewReader(fields["observation"]))
	observation, err := candidateObject(nested, map[string]bool{"phase": true, "code": true, "native_error": true, "native_operation": true, "native_hresult": true})
	if err != nil {
		return out, err
	}
	if observation["phase"] == nil || observation["code"] == nil {
		return out, fmt.Errorf("candidate observation missing field")
	}
	if nested.Decode(&extra) != io.EOF {
		return out, fmt.Errorf("candidate observation trailing data")
	}
	// Decode exact integer widths only after the duplicate/unknown field gate.
	if err = json.Unmarshal(data, &out); err != nil {
		return CandidateStatusReceipt{}, err
	}
	for _, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return CandidateStatusReceipt{}, fmt.Errorf("candidate status null field")
		}
	}
	for _, raw := range observation {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return CandidateStatusReceipt{}, fmt.Errorf("candidate observation null field")
		}
	}
	return out, nil
}
func candidateObject(d *json.Decoder, allowed map[string]bool) (map[string]json.RawMessage, error) {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("candidate status object required")
	}
	out := make(map[string]json.RawMessage, len(allowed))
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok || !allowed[name] || out[name] != nil {
			return nil, fmt.Errorf("candidate status field rejected")
		}
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil {
			return nil, err
		}
		out[name] = raw
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return nil, fmt.Errorf("candidate status object incomplete")
	}
	return out, nil
}
func candidateEnvelopeValid(v CandidateIdentity) bool {
	// A recorded launch/install error may precede a child process. Both numeric
	// fields must be absent together; no incomplete or borrowed candidate PID.
	if (v.PID == 0) != (v.Creation == 0) {
		return false
	}
	copy := v
	copy.PID, copy.Creation = 1, 1
	return candidateIdentityValid(copy)
}
