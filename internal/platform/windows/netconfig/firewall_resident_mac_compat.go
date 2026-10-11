package netconfig

import (
	"reflect"
	"slices"
)

const residentMacAppPath = "MSFT_NetApplicationFilter/AppPath"

// This compatibility is private to the complete compiled resident Mac scope.
// It is not a general CIM NULL default, native-write gate or legacy adoption.
func residentMacCompiledSpecs() []nativeRuleSpec {
	s, _ := residentSpecs("mac", "{A4611646-E050-4D25-B83E-633A5598F302}", "USB Link", "")
	return s
}

func residentMacAppPathReadScope(specs []nativeRuleSpec) bool {
	return reflect.DeepEqual(specs, residentMacCompiledSpecs())
}

func residentMacAppPathSpec(s nativeRuleSpec) bool {
	for _, compiled := range residentMacCompiledSpecs() {
		if s == compiled {
			return true
		}
	}
	return false
}

// Return a validation-only projection. Observations, fingerprints, protected
// receipts and PowerShell guards must retain the original raw NULL unchanged.
func residentConstraintProjection(got firewallConstraints, s nativeRuleSpec) firewallConstraints {
	if !residentMacAppPathSpec(s) || !slices.Equal(got[residentMacAppPath], []string{"NULL"}) {
		return got
	}
	copy := make(firewallConstraints, len(got))
	for key, value := range got {
		copy[key] = value
	}
	copy[residentMacAppPath] = []string{"S:Any"}
	return copy
}

func verifyResidentFirewallConstraints(got firewallConstraints, s nativeRuleSpec, enabled int32) error {
	return verifyFirewallConstraints(residentConstraintProjection(got, s), s, enabled)
}

// Native and resident readers share the same unchanged uniqueness boundary.
func firewallFilterCountProven(count int32) bool { return count == 1 }
