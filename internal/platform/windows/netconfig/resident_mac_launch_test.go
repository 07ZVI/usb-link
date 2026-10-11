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

func TestReadableReleaseStillRequiresAllResidentLaunchProofs(t *testing.T) {
	gate := `Local\USBLinkGatewayReady-0123456789abcdef01234567`
	exe := `C:\Program Files\USB Link\0.9.4\USB-Link.exe`
	for _, name := range []string{"mac-runtime-0.9.4", "mac-runtime-0.9.3"} {
		if err := ValidateResidentMacLaunch(true, false, false, false, true, true, "unified", gate, name, exe); err != nil {
			t.Fatal(err)
		}
		if err := ValidateResidentMacLaunch(true, false, false, false, true, false, "unified", gate, name, exe); err == nil {
			t.Fatal("missing kernel parent accepted")
		}
	}
	for _, name := range []string{"mac-runtime-dev", "mac-runtime-0.9.4-foreign", "mac-runtime-0.9", "mac-runtime-0.9.4/other"} {
		if err := ValidateResidentMacLaunch(true, false, false, false, true, true, "unified", gate, name, exe); err == nil {
			t.Fatal("foreign runtime admitted", name)
		}
	}
}
