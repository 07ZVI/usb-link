package netconfig

import (
	"errors"
	"sort"
	"strings"
	"syscall"
)

// Diagnostic data only. No field here is an interface, firewall or write grant.
type NativeReadCompatibilityReport struct {
	Schema       int                            `json:"schema"`
	ReadOnly     bool                           `json:"read_only"`
	WriteSupport string                         `json:"write_support"`
	Status       string                         `json:"status"`
	Stages       []NativeReadCompatibilityStage `json:"stages"`
}
type NativeReadCompatibilityStage struct {
	Phase       string                         `json:"phase"`
	Selector    string                         `json:"selector,omitempty"`
	Status      string                         `json:"status"`
	HRESULT     uint32                         `json:"hresult,omitempty"`
	NativeError uint32                         `json:"native_error,omitempty"`
	Fields      []NativeReadCompatibilityField `json:"fields,omitempty"`
}
type NativeReadCompatibilityField struct {
	Class       string  `json:"class"`
	Property    string  `json:"property"`
	Status      string  `json:"status"`
	Projection  string  `json:"projection,omitempty"`
	Number      *uint32 `json:"number,omitempty"`
	HRESULT     uint32  `json:"hresult,omitempty"`
	NativeError uint32  `json:"native_error,omitempty"`
}

func nativeReadErrorNumbers(err error) (uint32, uint32) {
	var h interface{ NativeHRESULT() uint32 }
	var native syscall.Errno
	var hr, code uint32
	if errors.As(err, &h) && int32(h.NativeHRESULT()) < 0 {
		hr = h.NativeHRESULT()
	}
	if errors.As(err, &native) {
		code = uint32(native)
	}
	return hr, code
}

// Report only compiled field names. Unknown caller map keys and actual string,
// array, owner, program, alias or identity values are never copied to output.
func nativeFirewallReadDifferences(s nativeRuleSpec, got firewallConstraints, observed map[string]NativeReadCompatibilityField) []NativeReadCompatibilityField {
	want := expectedFirewallConstraints(s, 1)
	keys := make([]string, 0, len(want))
	for key := range want {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]NativeReadCompatibilityField, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, "/", 2)
		class := parts[0]
		if class == "" {
			class = "MSFT_NetFirewallRule"
		}
		field := NativeReadCompatibilityField{Class: class, Property: parts[1], Status: "unavailable"}
		if metadata, exists := observed[key]; exists {
			// Metadata carries no input-controlled names/status text to this report.
			switch metadata.Projection {
			case "null", "empty", "string", "string_array", "unsigned_integer", "boolean", "unknown", "fixed_location":
				field.Projection = metadata.Projection
			}
			if nativeReadNumericFirewallProperty(parts[1]) {
				field.Number = metadata.Number
			}
			field.HRESULT, field.NativeError = metadata.HRESULT, metadata.NativeError
			if metadata.Status == "type_unknown" {
				field.Status = "type_unknown"
			}
		}
		if actual, exists := got[key]; exists {
			// Compare only this field through the existing exact/default contract.
			if equalFirewallReadParts(actual, want[key]) {
				field.Status = "match"
			} else if firewallDefaultMatches(key, actual, want[key], s.Protocol, got) {
				field.Status = "allowed_absence_projection"
			} else {
				field.Status = "mismatch"
			}
		}
		result = append(result, field)
	}
	return result
}

func nativeReadNumericFirewallProperty(field string) bool {
	switch field {
	case "Protocol", "Enabled", "Direction", "Action", "Profiles", "EdgeTraversalPolicy", "DynamicTransport", "InterfaceType", "Authentication", "Encryption":
		return true
	}
	return false
}
func equalFirewallReadParts(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nativeReadStageFieldsMatch(fields []NativeReadCompatibilityField) bool {
	for _, f := range fields {
		if f.Status != "match" && f.Status != "allowed_absence_projection" {
			return false
		}
	}
	return len(fields) > 0
}
