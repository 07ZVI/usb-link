package ipadsession

import (
	"encoding/json"
	"testing"
)

func TestUSBRememberMatchesSerialProductAndLayout(t *testing.T) {
	p := DefaultPreferences()
	root := `USB\VID_05AC&PID_12AB\ABCDEF1234567890`
	g := USBGrant(root, "12AB", "ncm-union-2-3-4-5-v1")
	if !g.Valid() || !p.RememberUSB(g) || !p.TrustedUSB(g) {
		t.Fatal("stable USB grant rejected")
	}
	for _, other := range []USBDeviceGrant{
		USBGrant(`USB\VID_05AC&PID_12AB\OTHER1234567890`, "12AB", "ncm-union-2-3-4-5-v1"),
		USBGrant(`USB\VID_05AC&PID_1903\ABCDEF1234567890`, "1903", "ncm-union-2-3-4-5-v1"),
		USBGrant(root, "12AB", "changed-layout"), {},
	} {
		if p.TrustedUSB(other) {
			t.Fatal("changed USB identity accepted")
		}
	}
	for _, bad := range []string{`USB\VID_05AC&PID_12AB&MI_00\ABCDEF1234567890`, `USB\VID_05AC&PID_12AB\6&ABC123&0&2`, `USB\VID_1234&PID_12AB\ABCDEF1234567890`, `USB\VID_05AC&PID_12AB\SHORT`} {
		if p.RememberUSB(USBGrant(bad, "12AB", "ncm")) {
			t.Fatal("unstable or unrelated identity remembered")
		}
	}
	p.USBDevices = nil
	if p.TrustedUSB(g) {
		t.Fatal("revocation failed")
	}
}

func TestLegacyPreferencesPreserveChoicesWithoutGrantingUSB(t *testing.T) {
	old := Preferences{Version: 1, Startup: true, IndependentUSB: false, Devices: []DeviceGrant{{DeviceIdentity("serial"), DeviceIdentity("key"), "iPad13,16"}}}
	b, _ := json.Marshal(old)
	p, e := ParsePreferences(b)
	if e != nil || p.Version != 2 || !p.Startup || p.IndependentUSB || len(p.Devices) != 1 || len(p.USBDevices) != 0 {
		t.Fatal("migration altered existing choices", p, e)
	}
	g := USBGrant(`USB\VID_05AC&PID_12AB\ABCDEF1234567890`, "12AB", "ncm")
	if p.TrustedUSB(g) {
		t.Fatal("certificate grant silently converted")
	}
	if !p.RememberUSB(g) {
		t.Fatal("new grant failed")
	}
	b, _ = json.Marshal(p)
	loaded, e := ParsePreferences(b)
	if e != nil || !loaded.TrustedUSB(g) {
		t.Fatal("USB grant did not persist")
	}
	p.Version = 1
	b, _ = json.Marshal(p)
	if _, e = ParsePreferences(b); e == nil {
		t.Fatal("USB grant in legacy schema accepted")
	}
}
