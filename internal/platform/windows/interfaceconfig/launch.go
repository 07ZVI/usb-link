package interfaceconfig

import (
	"errors"
	"regexp"
)

var macRuntimeBase = regexp.MustCompile(`^mac-runtime-([a-f0-9]{64}|[0-9]+\.[0-9]+\.[0-9]+)$`)

// ValidateMacOptimizationLaunch rejects unsupported optional combinations.
// This is not authorization: the bridge still requires fresh USB attachment,
// the held official factory handle and typed native identity at every mutation.
func ValidateMacOptimizationLaunch(dad, persistent, native, shared bool, profile, gateway, runtimeBase string) error {
	if !dad && !persistent {
		return nil
	}
	if !native || !shared || profile != "unified" || gateway == "" || !macRuntimeBase.MatchString(runtimeBase) {
		return errors.New("USB_MAC_OPTIMIZATION_OWNER_PLAN_REQUIRED")
	}
	return nil
}

// The dedicated DAD ledger does not enable the experimental network writer.
// Launch shape is only a precondition; actual held/USB/native proofs still run.
func ValidateMacOwnedDADLaunch(enabled, shared bool, profile, gateway, runtimeBase string) error {
	if !enabled {
		return nil
	}
	if !shared || profile != "unified" || gateway == "" || !macRuntimeBase.MatchString(runtimeBase) {
		return errors.New("USB_MAC_OWNED_DAD_OWNER_PLAN_REQUIRED")
	}
	return nil
}
