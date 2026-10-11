package netconfig

import (
	"errors"
	"regexp"
)

var residentMacRuntime = regexp.MustCompile(`^mac-runtime-([a-f0-9]{64}|[0-9]+\.[0-9]+\.[0-9]+)$`)
var residentMacGateway = regexp.MustCompile(`^Local\\USBLinkGatewayReady-[a-f0-9]{24}$`)

// Validation of a compiled launch shape only; not executable/adapter authority.
func ValidateResidentMacLaunch(selected, native, persistent, legacyDad, shared, parentBound bool, profile, gateway, runtimeBase, coreExe string) error {
	if !selected {
		if coreExe != "" {
			return errors.New("USB_RESIDENT_MAC_UNSELECTED_SOURCE")
		}
		return nil
	}
	if native || persistent || legacyDad || !shared || !parentBound || profile != "unified" || !residentMacGateway.MatchString(gateway) || !residentMacRuntime.MatchString(runtimeBase) || !validCoreExecutable(coreExe) {
		return errors.New("USB_RESIDENT_MAC_LAUNCH_PLAN_INVALID")
	}
	return nil
}

// Route the fixed core source to the feature which actually selected it. A
// module-only launch must not pretend that resident firewall is enabled. The
// syntax checks here do not replace inherited kernel-parent/source-pin proof.
func ValidateMacCoreSourceLaunch(resident, moduleHold, native, persistent, legacyDad, shared, parentBound bool, profile, gateway, runtimeBase, coreExe string) error {
	residentSource := coreExe
	if moduleHold && !resident {
		residentSource = ""
	}
	if err := ValidateResidentMacLaunch(resident, native, persistent, legacyDad, shared, parentBound, profile, gateway, runtimeBase, residentSource); err != nil {
		return err
	}
	return ValidateMacModuleHoldLaunch(moduleHold, native, persistent, legacyDad, shared, parentBound, profile, gateway, runtimeBase, coreExe)
}

// Module hold is independently selected by the installed parent's compiled
// launch, and admits only the fixed shared/unified legacy network shape.
func ValidateMacModuleHoldLaunch(selected, native, persistent, legacyDad, shared, parentBound bool, profile, gateway, runtimeBase, coreExe string) error {
	if !selected {
		return nil // The resident route still owns its unchanged source gate.
	}
	if native || persistent || legacyDad || !shared || !parentBound || profile != "unified" || !residentMacGateway.MatchString(gateway) || !residentMacRuntime.MatchString(runtimeBase) || !validCoreExecutable(coreExe) {
		return errors.New("USB_MAC_MODULE_HOLD_LAUNCH_PLAN_INVALID")
	}
	return nil
}
