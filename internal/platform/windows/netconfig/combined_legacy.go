package netconfig

import (
	"context"
	"fmt"
	"sync/atomic"
)

// ExecuteCombinedLegacyNetwork never treats a first fragment's marker as
// completion. The original executor must confirm the entire process/readback;
// fresh caller-owned identity and cancellation are checked on both sides.
func ExecuteCombinedLegacyNetwork(ctx context.Context, script string, owner func() error, run func(context.Context, string) error) error {
	if ctx == nil || script == "" || owner == nil || run == nil {
		return fmt.Errorf("USB_COMBINED_LEGACY_BATCH_INVALID")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := owner(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := run(ctx, script); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return owner()
}

var combinedLegacySelection atomic.Bool

// Selected before any owner starts. This combines only existing scripts at the
// same proven connection stage; it grants no interface or source authority.
func SetCombinedLegacyNetworkEnabled(v bool) { combinedLegacySelection.Store(v) }
func CombinedLegacyNetworkEnabled() bool     { return combinedLegacySelection.Load() }

// LegacyMacServiceScript preserves the entire FILES identity/token cleanup
// fragment and the entire protected core rule readback as an exact suffix.
// The caller still verifies the actual executable and current session before
// execution; neither this constructor nor its flag is an ownership proof.
func LegacyMacServiceScript(guid, token, executable string) (string, error) {
	files, err := FileReceiverRuleForProfile(guid, token, true, "unified")
	if err != nil {
		return "", err
	}
	core, err := CoreServicesRule(guid, "10.6.9.2", executable)
	if err != nil {
		return "", err
	}
	return files + "\n" + core, nil
}

func legacyRoleOperation(role string) string {
	switch role {
	case "shared_host", "mac_services", "ipad_permissions", "mac_recovery":
		return "legacy_" + role + "_script"
	default:
		return ""
	}
}

// BeginLegacyRoleScriptTiming measures an actual caller execution attempt,
// including failed completion/readback. These rows overlap the generic process
// counter and must not be summed with it. Unknown roles never enter diagnostics.
func BeginLegacyRoleScriptTiming(role string) func(error) {
	return beginNetworkTiming(legacyRoleOperation(role))
}

// ValidateCombinedLegacyMacLaunch checks only the fixed inherited launch shape.
// Actual source/USB/session ownership remains the caller's existing obligation.
func ValidateCombinedLegacyMacLaunch(selected, native, resident, shared, parentBound bool, profile, gateway, runtimeBase string) error {
	if !selected {
		return nil
	}
	if native || resident || !shared || !parentBound || profile != "unified" || !residentMacGateway.MatchString(gateway) || !residentMacRuntime.MatchString(runtimeBase) {
		return fmt.Errorf("USB_COMBINED_LEGACY_MAC_LAUNCH_INVALID")
	}
	return nil
}
