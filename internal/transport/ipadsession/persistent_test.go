package ipadsession

import (
	"strings"
	"testing"
)

func TestPersistentIPadPlanIsExplicitAndDoesNotWidenOldPlans(t *testing.T) {
	p := Plan{Version: 6, GUID: "{12345678-1234-1234-1234-123456789ABC}", Index: 7, LUID: 9, ServerIP: "10.6.9.1", Token: strings.Repeat("a", 24), PlannedAt: 100, CreatedAt: 101, HostFlags: &HostFlags{}, AddressMode: "persistent", PersistentSHA256: strings.Repeat("b", 64)}
	if !p.Valid() || p.LocalAddress() != "10.6.9.254" || p.PeerIP() != "10.6.9.3" || p.AddressPrefix() != 32 || p.AddressLifetime() != ^uint32(0) {
		t.Fatal("persistent scope changed", p)
	}
	a := AddressIdentity{Index: 7, LUID: 9, Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, CreatedAt: 101, ValidLifetime: ^uint32(0), PreferredLifetime: ^uint32(0)}
	if !OwnedAddress(p, a) {
		t.Fatal("exact completed persistent address rejected")
	}
	for _, mutation := range []func(*Plan){func(p *Plan) { p.Version = 5 }, func(p *Plan) { p.AddressMode = "" }, func(p *Plan) { p.PersistentSHA256 = "" }, func(p *Plan) { p.CreatedAt = 0 }, func(p *Plan) { p.ServerIP = "10.6.10.1" }, func(p *Plan) { p.HostFlags = nil }} {
		bad := p
		mutation(&bad)
		if bad.Valid() || OwnedAddress(bad, a) {
			t.Fatal("unproven persistent contract accepted")
		}
	}
	for _, mutation := range []func(*AddressIdentity){func(a *AddressIdentity) { a.CreatedAt++ }, func(a *AddressIdentity) { a.LUID++ }, func(a *AddressIdentity) { a.Index++ }, func(a *AddressIdentity) { a.ValidLifetime = 3600 }, func(a *AddressIdentity) { a.PreferredLifetime = 3600 }} {
		bad := a
		mutation(&bad)
		if OwnedAddress(p, bad) {
			t.Fatal("persistent original adopted another address")
		}
	}
	legacy := p
	legacy.Version, legacy.AddressMode, legacy.PersistentSHA256 = 5, "", ""
	if !legacy.Valid() || OwnedAddress(legacy, a) {
		t.Fatal("v5 contract was widened to infinite")
	}
}
