package ipadsession

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRememberRequiresFreshCertificateProofNotJustSerial(t *testing.T) {
	p := DefaultPreferences()
	g := DeviceGrant{DeviceIdentity("serial"), DeviceIdentity("key"), "iPad13,16"}
	if p.Remember(g, false) == nil {
		t.Fatal("unverified device remembered")
	}
	if p.Remember(g, true) != nil {
		t.Fatal("verified device rejected")
	}
	if !p.Trusted(g.Identity, g.Key, g.Product, true) || p.Trusted(g.Identity, g.Key, g.Product, false) || p.Trusted(g.Identity, DeviceIdentity("other key"), g.Product, true) || p.Trusted(DeviceIdentity("other serial"), g.Key, g.Product, true) {
		t.Fatal("device authorization mismatch")
	}
	p.Devices = nil
	if p.Trusted(g.Identity, g.Key, g.Product, true) {
		t.Fatal("revocation ineffective")
	}
}
func TestPreferenceSchemaRejectsCorruptionAndUnknownFields(t *testing.T) {
	p := DefaultPreferences()
	b, _ := json.Marshal(p)
	if _, e := ParsePreferences(b); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{`{"version":3}`, `{"version":1,"unknown":true}`, string(b) + "{}"} {
		if _, e := ParsePreferences([]byte(v)); e == nil {
			t.Fatal("invalid settings accepted")
		}
	}
}

func TestNetworkOnlyPreferenceDefaultsOnAndStoresOnlyExplicitOff(t *testing.T) {
	p := DefaultPreferences()
	if !p.NetworkOnlyEnabled() {
		t.Fatal("must default on")
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "network_only") {
		t.Fatal("default must not add a field", string(b))
	}
	got, err := ParsePreferences([]byte(`{"version":2,"startup":false,"independent_usb":true,"devices":[]}`))
	if err != nil || !got.NetworkOnlyEnabled() {
		t.Fatal("older files stay on", err)
	}
	p.NetworkOnlyOff = true
	b, _ = json.Marshal(p)
	got, err = ParsePreferences(b)
	if err != nil || got.NetworkOnlyEnabled() {
		t.Fatal("explicit off must round trip", err, string(b))
	}
	if _, err = ParsePreferences([]byte(`{"version":2,"network_only_off":"yes","devices":[]}`)); err == nil {
		t.Fatal("wrong type accepted")
	}
}
