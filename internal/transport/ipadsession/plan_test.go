package ipadsession

import (
	"strings"
	"testing"
)

func TestOwnedRulesAreUSBScopedAndCleanupRefusesOtherOwnership(t *testing.T) {
	p := Plan{Version: 1, GUID: "{12345678-1234-1234-1234-123456789abc}", LUID: 123, Index: 25, ServerIP: "10.77.123.1", Token: "0123456789abcdef01234567", PlannedAt: 1}
	setup, e := p.FirewallSetup()
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(setup, "-InterfaceAlias $a.Name") != 4 || strings.Contains(setup, "47990") || strings.Contains(setup, "Set-NetIPInterface") || strings.Contains(setup, "-Profile Private") {
		t.Fatal("unscoped or network-changing setup")
	}
	cleanup, e := p.FirewallCleanup()
	if e != nil || !strings.Contains(cleanup, "Rule ownership changed") || strings.Contains(cleanup, "Suhang*") {
		t.Fatal(e, cleanup)
	}
	p.ServerIP = "192.168.1.1"
	if _, e = p.FirewallSetup(); e == nil {
		t.Fatal("wrong subnet")
	}
	p.ServerIP = "10.77.123.1"
	p.Token = "'; evil"
	if _, e = p.FirewallCleanup(); e == nil {
		t.Fatal("script injection")
	}
	if ParseChosenSubnet("10.6.9.1") != "10.6.9.1" || ParseChosenSubnet("10.77.0.1") != "" || ParseChosenSubnet("10.77.123.1\nprivate data") != "" {
		t.Fatal("subnet output not strictly validated")
	}
}

func TestFixedSubnetAndLegacyRecoveryCompatibility(t *testing.T) {
	p := Plan{Version: 2, GUID: "{12345678-1234-1234-1234-123456789abc}", LUID: 7, Index: 9, ServerIP: "10.6.9.1", Token: "0123456789abcdef01234567", PlannedAt: 1}
	if !p.Valid() || p.PeerIP() != "10.6.9.2" || p.AddressLifetime() != 3600 {
		t.Fatal(p)
	}
	p.ServerIP = "10.6.10.1"
	if p.Valid() {
		t.Fatal("random subnet accepted")
	}
	p.Version = 1
	p.ServerIP = "10.77.100.1"
	if !p.Valid() || p.AddressLifetime() != 1800 {
		t.Fatal("legacy journal stranded")
	}
	s, e := SubnetScript(9, p.GUID, 1)
	if e != nil || !strings.Contains(s, "10.6.9.0") || !strings.Contains(s, "Get-NetRoute") || !strings.Contains(s, "throw 'USB subnet conflicts") || strings.Contains(s, "10.77") {
		t.Fatal(s, e)
	}
}

func TestConcurrentIPadSubnetPreservesLegacyRecovery(t *testing.T) {
	p := Plan{Version: 3, GUID: "{12345678-1234-1234-1234-123456789abc}", LUID: 7, Index: 9, ServerIP: "10.6.10.1", Token: "0123456789abcdef01234567", PlannedAt: 1}
	if !p.Valid() || p.PeerIP() != "10.6.10.2" {
		t.Fatal(p)
	}
	if _, e := p.FirewallSetup(); e != nil {
		t.Fatal(e)
	}
	if _, e := p.FirewallCleanup(); e != nil {
		t.Fatal(e)
	}
	script, e := ConcurrentSubnetScript(p.Index, p.GUID, 1)
	if e != nil || !strings.Contains(script, "10.6.10.0") || strings.Contains(script, "10.6.9.") || !strings.Contains(script, "Get-NetRoute") {
		t.Fatal("wrong concurrent subnet", e)
	}
	p.ServerIP = "10.6.9.1"
	if p.Valid() {
		t.Fatal("concurrent iPad plan collides with Mac")
	}
	p.Version = 2
	if !p.Valid() {
		t.Fatal("legacy journal can no longer be recovered")
	}
}

func TestSharedSubnetVersionPreservesOldRecovery(t *testing.T) {
	p := Plan{Version: 4, GUID: "{12345678-1234-1234-1234-123456789abc}", LUID: 7, Index: 9, ServerIP: "10.6.9.1", Token: "0123456789abcdef01234567", PlannedAt: 1}
	if !p.Valid() || p.PeerIP() != "10.6.9.3" || p.AddressPrefix() != 32 {
		t.Fatal(p)
	}
	a := AddressIdentity{LUID: 7, Index: 9, Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, ValidLifetime: 3600, PreferredLifetime: 3600, CreatedAt: 1}
	if !OwnedAddress(p, a) {
		t.Fatal("new journal cannot recover")
	}
	a.Prefix = 24
	if OwnedAddress(p, a) {
		t.Fatal("foreign subnet address accepted")
	}
	for _, v := range []int{2, 3} {
		p.Version = v
		if v == 3 {
			p.ServerIP = "10.6.10.1"
		}
		if !p.Valid() || p.AddressPrefix() != 24 {
			t.Fatal("old recovery stranded")
		}
	}
}
