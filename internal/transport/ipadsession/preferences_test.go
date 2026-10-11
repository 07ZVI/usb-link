package ipadsession

import (
	"encoding/json"
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
