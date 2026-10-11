package ipadsession

import "testing"

func TestOwnedAddressRecoveryRejectsRecreatedAndChangedAddress(t *testing.T) {
	p := Plan{Version: 1, GUID: "{12345678-1234-1234-1234-123456789abc}", LUID: 123, Index: 25, ServerIP: "10.77.42.1", Token: "0123456789abcdef01234567", PlannedAt: 1000000000, CreatedAt: 1005000000}
	a := AddressIdentity{LUID: 123, Index: 25, Prefix: 24, PrefixOrigin: 1, SuffixOrigin: 1, ValidLifetime: 1700, PreferredLifetime: 1700, CreatedAt: p.CreatedAt}
	if !OwnedAddress(p, a) {
		t.Fatal("owned address not recognized")
	}
	for _, change := range []func(*AddressIdentity){func(v *AddressIdentity) { v.LUID++ }, func(v *AddressIdentity) { v.Index++ }, func(v *AddressIdentity) { v.Prefix = 16 }, func(v *AddressIdentity) { v.PrefixOrigin = 3 }, func(v *AddressIdentity) { v.SuffixOrigin = 3 }, func(v *AddressIdentity) { v.ValidLifetime = 0xffffffff }, func(v *AddressIdentity) { v.PreferredLifetime = 0xffffffff }, func(v *AddressIdentity) { v.CreatedAt++ }} {
		b := a
		change(&b)
		if OwnedAddress(p, b) {
			t.Fatal("changed address accepted", b)
		}
	}
	p.CreatedAt = 0
	if !OwnedAddress(p, a) {
		t.Fatal("crash gap cannot recover")
	}
	a.CreatedAt = p.PlannedAt - 1
	if OwnedAddress(p, a) {
		t.Fatal("old address accepted")
	}
	a.CreatedAt = p.PlannedAt + 150000001
	if OwnedAddress(p, a) {
		t.Fatal("later unrelated address accepted")
	}
}
