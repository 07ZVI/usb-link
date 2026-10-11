package netconfig

import (
	"encoding/json"
	"errors"
)

// Fixed launch phases are diagnostics only, never source/adapter authority.
var macStartupCodes = map[string]string{
	"mac_launch_validate":       "MAC_LAUNCH_VALIDATE_FAILED",
	"mac_parent_source":         "MAC_PARENT_SOURCE_FAILED",
	"mac_runtime_acquire":       "MAC_RUNTIME_ACQUIRE_FAILED",
	"mac_usb_open":              "MAC_USB_OPEN_FAILED",
	"mac_usb_pair_capture":      "MAC_USB_PAIR_CAPTURE_FAILED",
	"mac_dad_originals":         "MAC_DAD_ORIGINALS_FAILED",
	"mac_factory_open":          "MAC_FACTORY_OPEN_FAILED",
	"mac_gateway_wait":          "MAC_GATEWAY_WAIT_FAILED",
	"mac_topology_verify":       "MAC_TOPOLOGY_VERIFY_FAILED",
	"mac_session_write":         "MAC_SESSION_WRITE_FAILED",
	"mac_typed_instance":        "MAC_TYPED_INSTANCE_FAILED",
	"mac_attached_owner":        "MAC_ATTACHED_OWNER_FAILED",
	"mac_dad_apply":             "MAC_DAD_APPLY_FAILED",
	"mac_source_begin":          "MAC_SOURCE_BEGIN_FAILED",
	"mac_resident_mac_plan":     "MAC_RESIDENT_MAC_PLAN_FAILED",
	"mac_resident_core_plan":    "MAC_RESIDENT_CORE_PLAN_FAILED",
	"mac_resident_network_plan": "MAC_RESIDENT_NETWORK_PLAN_FAILED",
	"mac_resident_batch_owner":  "MAC_RESIDENT_BATCH_OWNER_FAILED",
	"mac_resident_batch":        "MAC_RESIDENT_BATCH_FAILED",
	"mac_source_complete":       "MAC_SOURCE_COMPLETE_FAILED",
	"mac_transport_start":       "MAC_TRANSPORT_START_FAILED",
	"mac_session_cleanup":       "MAC_SESSION_CLEANUP_FAILED",
}

func macStartupOperationValid(operation string) bool { return macStartupCodes[operation] != "" }
func nativeDiagnosticCodeValid(v NativeStepDiagnostic) bool {
	return v.Code == "" || (macStartupCodes[v.Operation] != "" && v.Code == macStartupCodes[v.Operation])
}

// Exact existing owner failure codes, independent of untrusted error text.
// This literal table is reviewed with the corresponding actual source guards.
var macOwnerFailureCodes = map[string]bool{
	"CORE_BATCH_BINDING_CHANGED":                 true,
	"CORE_BATCH_COMPLETE_BINDING_CHANGED":        true,
	"CORE_BATCH_COMPLETE_SOURCE_CHANGED":         true,
	"CORE_BATCH_CREATION_CHANGED":                true,
	"CORE_BATCH_CREATION_UNREADABLE":             true,
	"CORE_BATCH_HANDLE_INVALID":                  true,
	"CORE_BATCH_HASH_FAILED":                     true,
	"CORE_BATCH_LASTWRITE_CHANGED":               true,
	"CORE_BATCH_OWNER_CHANGED":                   true,
	"CORE_BATCH_PID_CHANGED":                     true,
	"CORE_BATCH_PROCESS_EXITED":                  true,
	"CORE_BATCH_PROCESS_SOURCE_CHANGED":          true,
	"CORE_BATCH_SELF_CHANGED":                    true,
	"CORE_BATCH_SIZE_INVALID":                    true,
	"CORE_BATCH_SOURCE_HASH_CHANGED":             true,
	"CORE_BATCH_SOURCE_UNPROVEN":                 true,
	"MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN":      true,
	"MAC_RESIDENT_CONSUME_PLAN_UNPROVEN":         true,
	"MAC_RESIDENT_LIVE_SESSION_CHANGED":          true,
	"MAC_RESIDENT_RECORD_CHANGED":                true,
	"MAC_RESIDENT_RECORD_COMMIT_FAILED":          true,
	"MAC_RESIDENT_RECORD_CONSUME_FAILED":         true,
	"MAC_RESIDENT_RECORD_CREATE_FAILED":          true,
	"MAC_RESIDENT_RECORD_PLAN_UNPROVEN":          true,
	"MAC_RESIDENT_RECORD_PROTECTION_UNPROVEN":    true,
	"MAC_RESIDENT_RECORD_READBACK_FAILED":        true,
	"MAC_RESIDENT_RECORD_UNREADABLE":             true,
	"MAC_RESIDENT_RECORD_WRITE_FAILED":           true,
	"MAC_RESIDENT_RUNTIME_UNPROVEN":              true,
	"MAC_RESIDENT_SESSION_INVALID":               true,
	"USB_INTERFACE_GUID_CHANGED":                 true,
	"USB_INTERFACE_PROOF_CHANGED":                true,
	"USB_MAC_CURRENT_FACTORY_LEASE_CHANGED":      true,
	"USB_MAC_CURRENT_TYPED_INSTANCE_REQUIRED":    true,
	"USB_MAC_CURRENT_USB_ATTACHMENT_CHANGED":     true,
	"USB_MAC_RECREATE_INSTALLED_CHANGED":         true,
	"USB_MAC_RECREATE_INSTALLED_LIMIT":           true,
	"USB_MAC_RECREATE_INSTALLED_NOT_UNIQUE":      true,
	"USB_MAC_RECREATE_INSTALLED_UNREADABLE":      true,
	"USB_MAC_RECREATE_INSTANCE_CHANGED":          true,
	"USB_MAC_RECREATE_INSTANCE_UNPROVEN":         true,
	"USB_MAC_RECREATE_MAPPING_UNPROVEN":          true,
	"USB_MAC_RECREATE_NODE_CHANGED":              true,
	"USB_MAC_RECREATE_NODE_UNPROVEN":             true,
	"USB_MAC_RECREATE_SOURCE_INVALID":            true,
	"USB_MAC_RECREATE_SOURCE_MAPPING_CHANGED":    true,
	"USB_MAC_RECREATE_SOURCE_MAPPING_UNREADABLE": true,
	"USB_MAC_RECREATE_SOURCE_UNPROVEN":           true,
}

func macStartupCauseDetails(err error) ResidentFirewallErrorDetail {
	queue := []error{err}
	for n := 0; n < 32 && len(queue) > 0; n++ {
		cur := queue[0]
		queue = queue[1:]
		if cur == nil {
			continue
		}
		code := residentFailureCode(cur)
		if macOwnerFailureCodes[cur.Error()] {
			code = cur.Error()
		}
		if code != "USB_RESIDENT_OPERATION_FAILED" {
			hr, native := nativeReadErrorNumbers(cur)
			detail := ResidentFirewallErrorDetails(cur)
			return ResidentFirewallErrorDetail{Code: code, HRESULT: hr, NativeError: native, Field: detail.Field}
		}
		switch x := cur.(type) {
		case interface{ Unwrap() []error }:
			children := x.Unwrap()
			queue = append(queue, children[:min(len(children), 32)]...)
		case interface{ Unwrap() error }:
			queue = append(queue, x.Unwrap())
		}
	}
	return ResidentFirewallErrorDetails(err)
}

// Code projection uses only B's compiled exact-word vocabulary. It rejects
// prefixes/substrings and never treats a cause code as source/repair authority.
func nativeDiagnosticCauseValid(v NativeStepDiagnostic) bool {
	if v.CauseCode == "" {
		return v.NativeError == 0
	}
	if v.CauseCode == "CANCELLED" || v.CauseCode == "TIMEOUT" || v.CauseCode == "USB_RESIDENT_OPERATION_FAILED" {
		return true
	}
	return macOwnerFailureCodes[v.CauseCode] || residentFailureCode(errors.New(v.CauseCode)) == v.CauseCode
}

// This tracker is local to one run, called serially on its owning goroutine.
// Capture before deferred cleanup so Close cannot replace the initiating cause.
// Actual typed provider HRESULT/operation takes precedence over the enclosing
// fixed phase; arbitrary error text is neither parsed nor exported.
type FirstMacStartupFailure struct{ recorded bool }

func (v *FirstMacStartupFailure) Capture(operation string, err error) ([]byte, bool) {
	if v == nil || v.recorded || err == nil || !macStartupOperationValid(operation) {
		return nil, false
	}
	row := NativeStepDiagnostic{Schema: 1, Operation: operation, Code: macStartupCodes[operation]}
	if op, hr := NativeStepFailureDetails(err); op != "" {
		row.Operation, row.HRESULT, row.Code = op, hr, ""
	} else {
		var native interface{ NativeHRESULT() uint32 }
		if errors.As(err, &native) && int32(native.NativeHRESULT()) < 0 {
			row.HRESULT = native.NativeHRESULT()
		}
	}
	detail := macStartupCauseDetails(err)
	row.CauseCode, row.NativeError, row.CauseField = detail.Code, detail.NativeError, detail.Field
	if row.HRESULT == 0 && int32(detail.HRESULT) < 0 {
		row.HRESULT = detail.HRESULT
	}
	if !NativeStepDiagnosticValid(row) {
		return nil, false
	}
	b, e := json.Marshal(row)
	if e != nil || len(b) > 512 {
		return nil, false
	}
	v.recorded = true
	return b, true
}

// Both experiments inspect their actual opened USB pair. A flag alone never
// substitutes the capture or device.MatchesOpenedPair verification.
func MacLaunchNeedsUSBPair(legacyDad, persistent, resident, ownedDad bool) bool {
	return legacyDad || persistent || resident || ownedDad
}
