package netconfig

import (
	"context"
	"errors"
	"strings"
	"unicode/utf16"
)

// Plans are prepared by the scoped native reader and protected owner, never by
// UI text. Empty fragments mean reuse; Finish still freshly verifies each scope.
type ResidentPermissionPlan interface {
	Fragment() string
	Finish(context.Context) error
}

// Run at most one predefined PowerShell session for this connection stage.
// Partial process failure remains failure even if some plans verify: all plans
// get a final audit so already-created rules retain their exact obligations.
func CompleteResidentPermissionBatch(ctx context.Context, networkScript string, plans []ResidentPermissionPlan, run func(context.Context, string) error) error {
	if ctx == nil || run == nil || len(plans) > 8 {
		return errors.New("USB_RESIDENT_PERMISSION_BATCH_INVALID")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parts := []string{}
	residentPreludeSeen := false
	if strings.TrimSpace(networkScript) != "" {
		parts = append(parts, networkScript)
	}
	for _, p := range plans {
		if p == nil {
			return errors.New("USB_RESIDENT_PERMISSION_BATCH_INVALID")
		}
		if s := strings.TrimSpace(p.Fragment()); s != "" {
			if strings.Contains(s, residentPSProbe) {
				if residentPreludeSeen {
					s = strings.ReplaceAll(s, residentPSProbe, "")
				} else {
					residentPreludeSeen = true
				}
			}
			parts = append(parts, s)
		}
	}
	var result error
	if len(parts) != 0 {
		script := strings.Join(parts, "\n")
		if residentCommandUnits(script) > 32766 {
			result = errors.New("USB_RESIDENT_PERMISSION_COMMAND_LIMIT")
		} else {
			result = run(ctx, script)
		}
	}
	for _, p := range plans {
		result = errors.Join(result, p.Finish(ctx))
	}
	return errors.Join(result, ctx.Err())
}

// Conservative CreateProcess UTF-16 argument bound, including quote/backslash
// escaping, the fixed executable/arguments and the existing diagnostic wrapper.
func residentCommandUnits(s string) int {
	body := diagnosticScript(s)
	return len(utf16.Encode([]rune(body))) + strings.Count(body, "\"") + strings.Count(body, "\\") + 512
}
