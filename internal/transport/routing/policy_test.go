package routing

import (
	"net/netip"
	"testing"
	"time"
)

func TestInternetBoundaryIncludingPublicUpstreamLAN(t *testing.T) {
	ex := []string{"8.8.4.0/24"}
	for _, s := range []string{"10.6.9.3", "192.168.1.1", "172.16.2.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1", "8.8.4.4", "::1"} {
		if Public(netip.MustParseAddr(s), ex) {
			t.Fatal(s)
		}
	}
	if !Public(netip.MustParseAddr("1.1.1.1"), ex) {
		t.Fatal("public blocked")
	}
	for _, p := range PublicPrefixes(ex) {
		if !PublicPrefix(p, ex) {
			t.Fatal(p)
		}
	}
	if PublicPrefix(netip.MustParsePrefix("1.0.0.0/1"), nil) {
		t.Fatal("broad mask accepted")
	}
	if Public(netip.MustParseAddr("1.1.1.1"), []string{"bad"}) {
		t.Fatal("invalid exclusion accepted")
	}
}
func TestLeaseIsBoundToLiveCoreAndAttachment(t *testing.T) {
	now := time.Now()
	l := Lease{Schema: 1, Epoch: "0123456789abcdef0123456789abcdef", Root: "current", Expires: now.Add(5 * time.Second).Unix(), Enabled: true}
	if !l.Valid("current", now) || l.Valid("other", now) || l.Valid("current", now.Add(5*time.Second)) {
		t.Fatal("lease binding")
	}
	l.Expires = now.Add(time.Hour).Unix()
	if l.Valid("current", now) {
		t.Fatal("persistent consent accepted")
	}
}
func TestPrefixComplementMatchesAddressPolicy(t *testing.T) {
	ex := []string{"8.8.4.0/24", "1.2.3.4/32"}
	prefixes := PublicPrefixes(ex)
	for i := uint32(0); i < 10000; i++ {
		v := i * 429497
		addr := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		found := false
		for _, p := range prefixes {
			found = found || p.Contains(addr)
		}
		if found != Public(addr, ex) {
			t.Fatal(addr)
		}
	}
}
