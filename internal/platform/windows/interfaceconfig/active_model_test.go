package interfaceconfig

import (
	"strings"
	"testing"
)

func TestPersistentJournalRebindRequiresStableDoubleProof(t *testing.T) {
	old := Scope{Role: "host", GUID: HostGUID, Index: 7, LUID: 9}
	a := ActiveOwnership{Scope: Scope{Role: "host", GUID: HostGUID, Index: 17, LUID: 9}, Created: 142, ReceiptSHA256: strings.Repeat("a", 64)}
	if _, e := PlanOwnedPersistentRebind(old, 42, a, a); e != nil {
		t.Fatal("fresh volatile mapping rebind", e)
	}
	foreign := a
	foreign.Scope.LUID++
	if _, e := PlanOwnedPersistentRebind(old, 42, foreign, foreign); e == nil {
		t.Fatal("new factory LUID adopted without transaction")
	}
	changes := []ActiveOwnership{a, a, a, a}
	changes[0].Scope.GUID = MacGUID
	changes[1].Created++
	changes[2].ReceiptSHA256 = strings.Repeat("b", 64)
	changes[3].Scope.LUID++
	for i, b := range changes {
		if _, e := PlanOwnedPersistentRebind(old, 42, a, b); e == nil {
			t.Errorf("accepted unstable proof %d", i)
		}
	}
	if _, e := PlanOwnedPersistentRebind(old, 0, a, a); e == nil {
		t.Fatal("incomplete legacy journal adopted")
	}
	old.GUID = MacGUID
	if _, e := PlanOwnedPersistentRebind(old, 42, a, a); e == nil {
		t.Fatal("different owner scope adopted")
	}
}

func TestPersistentRebootRequiresFullFreshAddress(t *testing.T) {
	s := Scope{Role: "host", GUID: HostGUID, Index: 6, LUID: 9}
	good := activeAddress{Index: 6, LUID: 9, IP: "10.6.9.1", Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, DAD: 4, ValidLifetime: 0xffffffff, PreferredLifetime: 0xffffffff, Created: 42}
	if a, e := acceptPersistentActive(s, []activeAddress{good}, 1500); e != nil || a.Created != 42 {
		t.Fatal(a, e)
	}
	tests := []activeAddress{good, good, good, good, good, good, good, good, good, good, good}
	tests[0].Index++
	tests[1].LUID++
	tests[2].IP = "10.6.10.1"
	tests[3].Prefix = 24
	tests[4].PrefixOrigin = 3
	tests[5].SuffixOrigin = 3
	tests[6].DAD = 1
	tests[7].ValidLifetime = 3600
	tests[8].PreferredLifetime = 3600
	tests[9].Skip = true
	tests[10].Created = 0
	for i, a := range tests {
		if _, e := acceptPersistentActive(s, []activeAddress{a}, 1500); e == nil {
			t.Errorf("accepted change %d", i)
		}
	}
	if _, e := acceptPersistentActive(s, []activeAddress{good, good}, 1500); e == nil {
		t.Fatal("duplicate address")
	}
	if _, e := acceptPersistentActive(s, []activeAddress{good}, 9000); e == nil {
		t.Fatal("wrong MTU")
	}
}

func TestSecondaryPersistentAddressRequiresSkipAndExactInstance(t *testing.T) {
	for _, s := range []Scope{{Role: "mac", GUID: MacGUID, Index: 7, LUID: 9}, {Role: "ipad", GUID: "{12345678-ABCD-1234-ABCD-123456789ABC}", Index: 17, LUID: 19}} {
		a := activeAddress{Index: s.Index, LUID: s.LUID, IP: scopeAddress(s), Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, DAD: 4, ValidLifetime: 0xffffffff, PreferredLifetime: 0xffffffff, Skip: true, Created: 42}
		if _, e := acceptPersistentActive(s, []activeAddress{a}, 1500); e != nil {
			t.Fatal(s, e)
		}
		a.Skip = false
		if _, e := acceptPersistentActive(s, []activeAddress{a}, 1500); e == nil {
			t.Fatal("secondary source claim")
		}
		a.Skip = true
		a.LUID++
		if _, e := acceptPersistentActive(s, []activeAddress{a}, 1500); e == nil {
			t.Fatal("changed instance mapping")
		}
	}
}

func TestRetainedRuntimeKeepsCreatedWhileAllowingVerifiedMacJumbo(t *testing.T) {
	s := Scope{Role: "mac", GUID: MacGUID, Index: 7, LUID: 9}
	a := activeAddress{Index: 7, LUID: 9, IP: "10.6.9.253", Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, DAD: 4, ValidLifetime: 0xffffffff, PreferredLifetime: 0xffffffff, Skip: true, Created: 42}
	if _, e := acceptActiveMode(s, []activeAddress{a}, 16000, "retained_runtime", 42); e != nil {
		t.Fatal("negotiated runtime mtu", e)
	}
	if _, e := acceptActiveMode(s, []activeAddress{a}, 16001, "retained_runtime", 42); e == nil {
		t.Fatal("unknown jumbo")
	}
	if _, e := acceptActiveMode(s, []activeAddress{a}, 16000, "persistent", 0); e == nil {
		t.Fatal("jumbo accepted as boot proof")
	}
	if _, e := acceptActiveMode(s, []activeAddress{a}, 16000, "retained_runtime", 41); e == nil {
		t.Fatal("changed active Created")
	}
	s.Role = "ipad"
	s.GUID = "{12345678-ABCD-1234-ABCD-123456789ABC}"
	a.IP = "10.6.9.254"
	if _, e := acceptActiveMode(s, []activeAddress{a}, 16000, "retained_runtime", 42); e == nil {
		t.Fatal("iPad negotiated mtu guessed")
	}
}
