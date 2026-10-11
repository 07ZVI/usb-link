package usbhost

import "testing"

func TestNonpresentRecoveryRequiresCompletedUnchangedLUIDAndAbsentAddress(t *testing.T) {
	p := priorJournal()
	if e := validateNonpresentRecoveryOwnership(p, p.LUID, 0); e != nil {
		t.Fatal(e)
	}
	for _, count := range []int{-1, 1, 2} {
		if validateNonpresentRecoveryOwnership(p, p.LUID, count) == nil {
			t.Fatal("nonabsent address replay admitted", count)
		}
	}
	for _, luid := range []uint64{0, p.LUID + 1} {
		if validateNonpresentRecoveryOwnership(p, luid, 0) == nil {
			t.Fatal("changed original LUID admitted")
		}
	}
	for _, mutate := range []func(*journal){func(p *journal) { p.Created = 0 }, func(p *journal) { p.Index = 0 }, func(p *journal) { p.LUID = 0 }} {
		bad := p
		mutate(&bad)
		if validateNonpresentRecoveryOwnership(bad, bad.LUID, 0) == nil {
			t.Fatal("incomplete creation receipt admitted")
		}
	}
	// The actual reboot case changes only interface index. No stamp, token or
	// original LUID may be replaced to acquire a newly enumerated device.
	next, state, e := rebindRecovery(p, 24, p.LUID, nil)
	if e != nil || state != "absent" || next.Index != 24 || next.LUID != p.LUID || next.Created != p.Created || next.Token != p.Token {
		t.Fatal("exact absent-address boot replay", e)
	}
}
