package ipadsession

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDescriptorGrantDoesNotUpgradeOldInstanceConsent(t *testing.T) {
	const serial, product, layout = "ABCDEF1234567890", "iPad Pro", "photo-mux-cfg3-to-ncm-union-cfg5-v3"
	old := USBGrant(`USB\VID_05AC&PID_12AB\`+serial, "12AB", layout+"-model:"+product)
	fresh := USBDescriptorGrant(serial, product, "12AB", layout)
	p := DefaultPreferences()
	if !fresh.Valid() || !old.Valid() || !p.RememberUSB(old) || p.TrustedUSB(fresh) {
		t.Fatal("unread old instance consent acquired descriptor provenance")
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ParsePreferences(encoded)
	if err != nil || !loaded.TrustedUSB(old) || loaded.TrustedUSB(fresh) {
		t.Fatal("parse silently promoted or deleted old consent", err)
	}
	if !loaded.RememberUSB(fresh) || !loaded.TrustedUSB(fresh) || len(loaded.USBDevices) != 2 {
		t.Fatal("first new confirmation failed to preserve old record")
	}
	for _, changed := range []USBDeviceGrant{
		USBDescriptorGrant(serial+"1", product, "12AB", layout),
		USBDescriptorGrant(serial, "iPad Air", "12AB", layout),
		USBDescriptorGrant(serial, product, "12AB", layout+"-changed"),
		USBDescriptorGrant(strings.ToLower(serial), product, "12AB", layout),
	} {
		if loaded.TrustedUSB(changed) {
			t.Fatal("changed raw descriptor or layout inherited prior permission")
		}
	}
	encoded, _ = json.Marshal(fresh)
	if strings.Contains(string(encoded), serial) || strings.Contains(string(encoded), product) {
		t.Fatal("grant persisted raw USB identifier instead of digests")
	}
}

func TestDescriptorGrantRejectsLocationAndPresentationFallback(t *testing.T) {
	for _, tc := range []struct{ serial, product, pid, layout string }{
		{"", "iPad", "12AB", "ncm"}, {"6&ABC123&0&2", "iPad", "12AB", "ncm"},
		{"SHORT", "iPad", "12AB", "ncm"}, {strings.Repeat("a", 129), "iPad", "12AB", "ncm"},
		{"ABCDEF123456", "", "12AB", "ncm"}, {"ABCDEF123456", "iPhone", "12AB", "ncm"},
		{"ABCDEF123456", "iPadForgery", "12AB", "ncm"}, {"ABCDEF123456", " iPad", "12AB", "ncm"},
		{"ABCDEF123456", "iPad\x00", "12AB", "ncm"}, {"ABCDEF123456", "iPad\uFFFD", "12AB", "ncm"},
		{"ABCDEF123456", "iPad", "1903", "ncm"}, {"ABCDEF123456", "iPad", "12AB", ""},
	} {
		if USBDescriptorGrant(tc.serial, tc.product, tc.pid, tc.layout).Valid() {
			t.Fatal("unproven descriptor identity accepted", tc)
		}
	}
	if !USBDescriptorGrant("ABCDEF123456", "iPad", "12AB", "ncm").Valid() {
		t.Fatal("real generic iProduct description incorrectly requires a detailed model")
	}
}
