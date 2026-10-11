package netconfig

import (
	"strings"
	"testing"
)

func TestResidentMacLaunchKeepsNativeAndPersistentExperimentsSeparate(t *testing.T) {
	base := strings.Repeat("a", 64)
	gate := `Local\USBLinkGatewayReady-0123456789abcdef01234567`
	exe := `C:\Program Files\USB Link\0.8.108\USB-Link.exe`
	valid := func(native, persistent, legacy, shared, parent bool, profile, event, runtime, source string) error {
		return ValidateResidentMacLaunch(true, native, persistent, legacy, shared, parent, profile, event, runtime, source)
	}
	if e := valid(false, false, false, true, true, "unified", gate, "mac-runtime-"+base, exe); e != nil {
		t.Fatal(e)
	}
	for _, e := range []error{
		valid(true, false, false, true, true, "unified", gate, "mac-runtime-"+base, exe), valid(false, true, false, true, true, "unified", gate, "mac-runtime-"+base, exe), valid(false, false, true, true, true, "unified", gate, "mac-runtime-"+base, exe), valid(false, false, false, false, true, "unified", gate, "mac-runtime-"+base, exe), valid(false, false, false, true, false, "unified", gate, "mac-runtime-"+base, exe), valid(false, false, false, true, true, "legacy", gate, "mac-runtime-"+base, exe), valid(false, false, false, true, true, "unified", "", "mac-runtime-"+base, exe), valid(false, false, false, true, true, "unified", gate, "other-runtime-"+base, exe), valid(false, false, false, true, true, "unified", gate, "mac-runtime-"+base, ""),
	} {
		if e == nil {
			t.Fatal("unsupported resident plan admitted")
		}
	}
	if e := ValidateResidentMacLaunch(false, false, false, false, true, true, "unified", gate, "mac-runtime-"+base, exe); e == nil {
		t.Fatal("core source accepted while mode disabled")
	}
}
