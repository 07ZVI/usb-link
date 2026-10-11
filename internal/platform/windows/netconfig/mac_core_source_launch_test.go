package netconfig

import (
	"strings"
	"testing"
)

func TestMacCoreSourceLaunchRoutesModuleAndResidentSelections(t *testing.T) {
	gate := `Local\USBLinkGatewayReady-0123456789abcdef01234567`
	runtime := "mac-runtime-" + strings.Repeat("a", 64)
	exe := `C:\Program Files\USB Link\0.8.121\USB-Link.exe`
	for _, tc := range []struct {
		name           string
		resident, hold bool
		source         string
	}{
		{"neither", false, false, ""}, {"resident_only", true, false, exe},
		{"module_only", false, true, exe}, {"resident_and_module", true, true, exe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateMacCoreSourceLaunch(tc.resident, tc.hold, false, false, false, true, true, "unified", gate, runtime, tc.source); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Preserve the original gate: arbitrary core-exe cannot become selected by
	// merely adding a source argument to a launch with both features disabled.
	if err := ValidateMacCoreSourceLaunch(false, false, false, false, false, true, true, "unified", gate, runtime, exe); err == nil || err.Error() != "USB_RESIDENT_MAC_UNSELECTED_SOURCE" {
		t.Fatal("unselected core source accepted", err)
	}
	// The old resident validator itself remains unchanged; module selection is
	// deliberately routed around its unselected-source gate, never enabled.
	if err := ValidateResidentMacLaunch(false, false, false, false, true, true, "unified", gate, runtime, exe); err == nil {
		t.Fatal("resident authority broadened")
	}
}

func TestMacModuleOnlyLaunchRetainsStrictFixedPlan(t *testing.T) {
	type plan struct {
		native, persistent, legacy, shared, parent bool
		profile, gate, runtime, source             string
	}
	valid := plan{shared: true, parent: true, profile: "unified", gate: `Local\USBLinkGatewayReady-0123456789abcdef01234567`, runtime: "mac-runtime-" + strings.Repeat("a", 64), source: `C:\Program Files\USB Link\0.8.121\USB-Link.exe`}
	for name, change := range map[string]func(*plan){
		"native": func(p *plan) { p.native = true }, "persistent": func(p *plan) { p.persistent = true }, "legacy_dad": func(p *plan) { p.legacy = true },
		"no_shared_host": func(p *plan) { p.shared = false }, "no_kernel_parent": func(p *plan) { p.parent = false }, "wrong_profile": func(p *plan) { p.profile = "legacy" },
		"missing_gate": func(p *plan) { p.gate = "" }, "wrong_gate_scope": func(p *plan) { p.gate = strings.Replace(p.gate, "Local", "Global", 1) },
		"unknown_runtime": func(p *plan) { p.runtime = "other-runtime-" + strings.Repeat("a", 64) }, "missing_source": func(p *plan) { p.source = "" },
		"relative_source": func(p *plan) { p.source = "USB-Link.exe" }, "unsafe_source": func(p *plan) { p.source += "\n" },
	} {
		t.Run(name, func(t *testing.T) {
			p := valid
			change(&p)
			err := ValidateMacCoreSourceLaunch(false, true, p.native, p.persistent, p.legacy, p.shared, p.parent, p.profile, p.gate, p.runtime, p.source)
			if err == nil || err.Error() != "USB_MAC_MODULE_HOLD_LAUNCH_PLAN_INVALID" {
				t.Fatal("module-only invalid plan admitted", err)
			}
		})
	}
}
