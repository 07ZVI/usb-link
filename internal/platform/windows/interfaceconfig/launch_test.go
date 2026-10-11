package interfaceconfig

import (
	"strings"
	"testing"
)

func TestMacOptionalLaunchCannotEnterUnownedLegacyPlan(t *testing.T) {
	base := "mac-runtime-" + strings.Repeat("a", 64)
	if e := ValidateMacOptimizationLaunch(false, false, false, false, "legacy", "", "anything"); e != nil {
		t.Fatal("OFF changed ordinary flow", e)
	}
	for _, flags := range [][2]bool{{true, false}, {false, true}, {true, true}} {
		if e := ValidateMacOptimizationLaunch(flags[0], flags[1], true, true, "unified", "owned-gateway", base); e != nil {
			t.Fatal(e)
		}
		cases := []struct {
			native, shared         bool
			profile, gateway, base string
		}{{false, true, "unified", "g", base}, {true, false, "unified", "g", base}, {true, true, "legacy", "g", base}, {true, true, "unified", "", base}, {true, true, "unified", "g", "mac-runtime-invalid"}, {true, true, "unified", "g", base + "-foreign"}}
		for _, c := range cases {
			if ValidateMacOptimizationLaunch(flags[0], flags[1], c.native, c.shared, c.profile, c.gateway, c.base) == nil {
				t.Fatal("optional optimization accepted unsupported owner plan", c)
			}
		}
	}
}

func TestReadableRuntimeKeepsDADAndOptimizationLaunchConstraints(t *testing.T) {
	if err := ValidateMacOwnedDADLaunch(true, true, "unified", "owned-gate", "mac-runtime-0.9.4"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMacOwnedDADLaunch(true, true, "legacy", "owned-gate", "mac-runtime-0.9.4"); err == nil {
		t.Fatal("wrong profile accepted")
	}
	if err := ValidateMacOptimizationLaunch(true, true, true, true, "unified", "owned-gate", "mac-runtime-0.9.4"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMacOptimizationLaunch(true, true, false, true, "unified", "owned-gate", "mac-runtime-0.9.4"); err == nil {
		t.Fatal("unselected native mode accepted")
	}
}
