package netconfig

import (
	"context"
	"sync"
)

var residentRoles = []string{"host", "mac", "ipad", "core_mac", "core_ipad"}

type ResidentFirewallFailure struct {
	Role                  string `json:"role"`
	Calls                 uint64 `json:"calls"`
	Failures              uint64 `json:"failures"`
	LastPhase             string `json:"last_phase,omitempty"`
	FirstFailurePhase     string `json:"first_failure_phase,omitempty"`
	FirstErrorCode        string `json:"first_error_code,omitempty"`
	FirstCauseField       string `json:"first_cause_field,omitempty"`
	HRESULT               uint32 `json:"hresult,omitempty"`
	NativeError           uint32 `json:"native_error,omitempty"`
	CompletedAfterFailure bool   `json:"completed_after_failure,omitempty"`
}

var residentFailureState = struct {
	sync.Mutex
	values map[string]ResidentFirewallFailure
}{values: map[string]ResidentFirewallFailure{}}

// Fixed errors only: source strings, callbacks, paths and joined raw errors are
// never copied. Unknown actual failures still produce a fixed failure result.
func residentFailureCode(err error) string {
	if err == nil {
		return ""
	}
	if err == context.Canceled {
		return "CANCELLED"
	}
	if err == context.DeadlineExceeded {
		return "TIMEOUT"
	}
	switch err.Error() {
	case "USB_RESIDENT_SCOPE_INVALID", "USB_RESIDENT_SOURCE_INVALID", "USB_RESIDENT_ROLE_INVALID", "USB_RESIDENT_OWNER_REQUIRED", "USB_RESIDENT_HOST_PROOF_REQUIRED", "USB_RESIDENT_PLAN_INVALID", "USB_RESIDENT_UNKNOWN_RULE", "USB_RESIDENT_FOREIGN_SCOPE", "USB_RESIDENT_CONSTRAINT_INCOMPLETE", "USB_RESIDENT_CONSTRAINT_TYPE_UNKNOWN", "USB_RESIDENT_CONSTRAINT_CHANGED", "USB_RESIDENT_LEDGER_INVALID", "USB_RESIDENT_LEDGER_LIMIT", "USB_RESIDENT_LEDGER_SCOPE_INVALID", "USB_RESIDENT_LEDGER_SCOPE_CHANGED", "USB_RESIDENT_LEDGER_CHANGED", "USB_RESIDENT_LEDGER_REQUIRED", "USB_RESIDENT_LEDGER_ROLE_CHANGED", "USB_RESIDENT_LEDGER_READBACK_FAILED", "USB_RESIDENT_LEDGER_ABSENCE_UNPROVEN", "USB_RESIDENT_STORE_UNPROVEN", "USB_RESIDENT_INTENT_UNREADABLE", "USB_RESIDENT_INTENT_PROTECTION_UNPROVEN", "USB_RESIDENT_RULE_MISSING", "USB_RESIDENT_RULE_REMAINS", "USB_RESIDENT_LEGACY_SOURCE_REQUIRED", "USB_NATIVE_FIREWALL_SCOPE_CHANGED", "USB_NATIVE_FIREWALL_CONSTRAINT_INCOMPLETE", "USB_NATIVE_FIREWALL_CONSTRAINT_UNKNOWN", "USB_NATIVE_FIREWALL_CONSTRAINT_NULL", "USB_NATIVE_FIREWALL_FILTER_UNPROVEN", "USB_NATIVE_FIREWALL_FILTER_AMBIGUOUS", "USB_NATIVE_FIREWALL_ENUMERATION_INCOMPLETE", "USB_NATIVE_FIREWALL_ENUMERATION_AMBIGUOUS", "USB_NATIVE_FIREWALL_CONSTRAINT_TYPE_UNKNOWN", "USB_NATIVE_FIREWALL_PROTOCOL_TYPE_UNKNOWN", "USB_NATIVE_FIREWALL_PROTOCOL_UNKNOWN", "USB_NATIVE_FIREWALL_BOOLEAN_UNKNOWN", "USB_NATIVE_FIREWALL_ENUM_UNKNOWN", "USB_NATIVE_FIREWALL_DYNAMIC_CONSTRAINT_UNKNOWN", "USB_NATIVE_FIREWALL_INTERFACE_CHANGED", "USB_NATIVE_FIREWALL_INTERFACE_INVALID", "USB_NATIVE_PROFILE_RECOVERY_OWNER_UNPROVEN", "USB_NATIVE_PROFILE_RECOVERY_MAPPING_CHANGED", "USB_NATIVE_PROFILE_RECOVERY_DRIVER_UNPROVEN", "USB_NATIVE_PROFILE_RECOVERY_PNP_NOT_UNIQUE", "USB_NATIVE_PROFILE_RECOVERY_RESTART_UNPROVEN":
		return err.Error()
	}
	return "USB_RESIDENT_OPERATION_FAILED"
}

type ResidentFirewallErrorDetail struct {
	Code        string `json:"code,omitempty"`
	Field       string `json:"field,omitempty"`
	HRESULT     uint32 `json:"hresult,omitempty"`
	NativeError uint32 `json:"native_error,omitempty"`
}

// Inspect only bounded actual causes. No prefix, substring, raw message or
// arbitrary callback identity becomes a published code or repair permission.
func ResidentFirewallErrorDetails(err error) ResidentFirewallErrorDetail {
	if err == nil {
		return ResidentFirewallErrorDetail{}
	}
	queue := []error{err}
	for n := 0; n < 32 && len(queue) > 0; n++ {
		cur := queue[0]
		queue = queue[1:]
		if cur == nil {
			continue
		}
		if typed, ok := cur.(*firewallConstraintFailure); ok && ValidFirewallConstraintField(typed.field) {
			hr, native := nativeReadErrorNumbers(typed.cause)
			return ResidentFirewallErrorDetail{Code: residentFailureCode(typed), Field: typed.field, HRESULT: hr, NativeError: native}
		}
		code := residentFailureCode(cur)
		if code != "USB_RESIDENT_OPERATION_FAILED" {
			hr, native := nativeReadErrorNumbers(cur)
			return ResidentFirewallErrorDetail{Code: code, HRESULT: hr, NativeError: native}
		}
		switch v := cur.(type) {
		case interface{ Unwrap() []error }:
			children := v.Unwrap()
			if len(children) > 32 {
				children = children[:32]
			}
			queue = append(queue, children...)
		case interface{ Unwrap() error }:
			queue = append(queue, v.Unwrap())
		}
	}
	hr, native := nativeReadErrorNumbers(err)
	return ResidentFirewallErrorDetail{Code: "USB_RESIDENT_OPERATION_FAILED", HRESULT: hr, NativeError: native}
}

func recordResidentOperation(role, phase string, err error) {
	fixed := false
	for _, r := range residentRoles {
		fixed = fixed || role == r
	}
	if !fixed || (phase != "prepare" && phase != "finish") {
		return
	}
	residentFailureState.Lock()
	defer residentFailureState.Unlock()
	v := residentFailureState.values[role]
	v.Role = role
	v.Calls++
	v.LastPhase = phase
	if err != nil {
		v.Failures++
		if v.FirstErrorCode == "" {
			detail := ResidentFirewallErrorDetails(err)
			v.FirstErrorCode = detail.Code
			v.FirstCauseField = detail.Field
			v.FirstFailurePhase = phase
			v.HRESULT, v.NativeError = detail.HRESULT, detail.NativeError
		}
	} else if phase == "finish" && v.FirstErrorCode != "" {
		v.CompletedAfterFailure = true
	}
	residentFailureState.values[role] = v
}

// Read-only process-local history. First failures are retained after later
// completion, explicitly marked; these values never authorize Ready or repair.
func ResidentFirewallFailureDiagnostics() []ResidentFirewallFailure {
	residentFailureState.Lock()
	defer residentFailureState.Unlock()
	out := make([]ResidentFirewallFailure, 0, len(residentRoles))
	for _, r := range residentRoles {
		v := residentFailureState.values[r]
		v.Role = r
		out = append(out, v)
	}
	return out
}

type ResidentFirewallDiagnosticRole struct {
	Role                 string                  `json:"role"`
	Phase                string                  `json:"phase"`
	LedgerPresent        bool                    `json:"ledger_present"`
	ExpectedRuleCount    int                     `json:"expected_rule_count"`
	KnownNameCount       int                     `json:"known_name_count"`
	PresentRules         int                     `json:"present_rules"`
	AbsentRules          int                     `json:"absent_rules"`
	UnreadableRules      int                     `json:"unreadable_rules"`
	ObservationErrorCode string                  `json:"observation_error_code,omitempty"`
	ObservationField     string                  `json:"observation_field,omitempty"`
	HRESULT              uint32                  `json:"hresult,omitempty"`
	NativeError          uint32                  `json:"native_error,omitempty"`
	Failure              ResidentFirewallFailure `json:"actual_operation_history"`
}
type ResidentFirewallDiagnosticReport struct {
	Schema        int                              `json:"schema"`
	ReadOnly      bool                             `json:"read_only"`
	Scope         string                           `json:"scope"`
	LiveProofUsed bool                             `json:"live_proof_used"`
	Status        string                           `json:"status"`
	Roles         []ResidentFirewallDiagnosticRole `json:"roles"`
}
