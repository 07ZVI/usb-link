package usbhost

import (
	"encoding/json"
	"errors"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func priorJournal() journal {
	return journal{Version: 1, GUID: usbaddress.HostGUID, Index: 23, LUID: 230, Planned: 100, Created: 110, Token: "0123456789abcdef01234567"}
}
func ownedRecoveryAddress() recoveryAddress {
	return recoveryAddress{Index: 31, LUID: 310, Address: [4]byte{10, 6, 9, 1}, Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, ValidLifetime: 3600, PreferredLifetime: 3600, Created: 110}
}

func TestRecoveryAcrossBootPreservesOwnership(t *testing.T) {
	p := priorJournal()
	for _, addresses := range [][]recoveryAddress{nil, {ownedRecoveryAddress()}} {
		next, _, e := rebindRecovery(p, 31, 310, addresses)
		if e != nil {
			t.Fatal(e)
		}
		if next.Index != 31 || next.LUID != 310 {
			t.Fatal("boot-local mapping not refreshed")
		}
		next.Index, next.LUID = p.Index, p.LUID
		if next != p {
			t.Fatal("original address ownership was replaced")
		}
	}
}

func TestRecoveryRequiresUniqueExactHostIdentity(t *testing.T) {
	good := hostIdentity{GUID: usbaddress.HostGUID, Alias: usbaddress.HostName, Type: 53, Index: 31, LUID: 310}
	if e := validateHostCandidates([]hostIdentity{good}); e != nil {
		t.Fatal(e)
	}
	if e := validateHostCandidates([]hostIdentity{good, good}); e == nil {
		t.Fatal("duplicate identity accepted")
	}
	for _, mutate := range []func(*hostIdentity){func(p *hostIdentity) { p.GUID = "foreign" }, func(p *hostIdentity) { p.Alias = "other" }, func(p *hostIdentity) { p.Type = 6 }, func(p *hostIdentity) { p.Index = 0 }, func(p *hostIdentity) { p.LUID = 0 }} {
		bad := good
		mutate(&bad)
		if e := validateHostCandidates([]hostIdentity{bad}); e == nil {
			t.Fatal("foreign identity accepted")
		}
	}
}

func TestRecoveryRejectsForeignAddressWithoutCheckpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*recoveryAddress)
	}{
		{"creation", func(a *recoveryAddress) { a.Created++ }},
		{"prefix", func(a *recoveryAddress) { a.Prefix = 24 }},
		{"prefix-origin", func(a *recoveryAddress) { a.PrefixOrigin = 3 }},
		{"unknown-full-width-origin", func(a *recoveryAddress) { a.PrefixOrigin = 257 }},
		{"suffix-origin", func(a *recoveryAddress) { a.SuffixOrigin = 3 }},
		{"lifetime", func(a *recoveryAddress) { a.ValidLifetime = 0xffffffff }},
		{"preferred-lifetime", func(a *recoveryAddress) { a.PreferredLifetime = 0xffffffff }},
		{"other-address", func(a *recoveryAddress) { a.Address[3] = 8 }},
		{"wrong-luid", func(a *recoveryAddress) { a.LUID++ }},
		{"wrong-index", func(a *recoveryAddress) { a.Index++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ownedRecoveryAddress()
			tc.mutate(&a)
			if _, _, e := rebindRecovery(priorJournal(), 31, 310, []recoveryAddress{a}); e == nil {
				t.Fatal("accepted foreign address")
			}
		})
	}
	if _, _, e := rebindRecovery(priorJournal(), 31, 310, []recoveryAddress{ownedRecoveryAddress(), ownedRecoveryAddress()}); e == nil {
		t.Fatal("accepted duplicate rows")
	}
	a := ownedRecoveryAddress()
	a.Address[3] = 8
	if _, _, e := rebindRecovery(priorJournal(), 31, 310, []recoveryAddress{ownedRecoveryAddress(), a}); e == nil {
		t.Fatal("accepted additional foreign address")
	}
	p := priorJournal()
	p.Index, p.LUID, p.Created = 0, 0, 0
	if _, _, e := rebindRecovery(p, 31, 310, []recoveryAddress{ownedRecoveryAddress()}); e == nil {
		t.Fatal("intent without creation checkpoint accepted an address")
	}
}

func TestMappingCheckpointFailuresPreventMutation(t *testing.T) {
	p := priorJournal()
	next, _, e := rebindRecovery(p, 31, 310, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"write", "read", "old-readback", "corrupt-readback", "good"} {
		t.Run(fault, func(t *testing.T) {
			writes, removes := 0, 0
			e := checkpointMapping(p, next, func(j journal) error {
				writes++
				if fault == "write" {
					return errors.New("disk full")
				}
				return nil
			}, func() ([]byte, error) {
				if fault == "read" {
					return nil, errors.New("unreadable")
				}
				if fault == "corrupt-readback" {
					return []byte("{}"), nil
				}
				if fault == "old-readback" {
					return json.Marshal(p)
				}
				return json.Marshal(next)
			})
			// This is the recovery transaction's mandatory boundary before native removal.
			if e == nil {
				removes++
			}
			if writes != 1 || (fault == "good" && removes != 1) || (fault != "good" && removes != 0) {
				t.Fatalf("writes=%d removes=%d error=%v", writes, removes, e)
			}
		})
	}
}

func TestJournalRejectsIncompleteAndUnknownOwnership(t *testing.T) {
	p := priorJournal()
	good, _ := json.Marshal(p)
	if _, e := decodeJournal(good); e != nil {
		t.Fatal(e)
	}
	// A completed checkpoint is authoritative even if system time changed or
	// the native creation timestamp has coarser precision than Planned.
	clockShift := p
	clockShift.Created = p.Planned - 1
	shifted, _ := json.Marshal(clockShift)
	if _, e := decodeJournal(shifted); e != nil {
		t.Fatal("discarded completed native creation checkpoint", e)
	}
	for _, bad := range [][]byte{[]byte("{}"), append(append([]byte{}, good...), []byte(" {}")...), []byte(`{"Version":1,"GUID":"wrong","Planned":1,"Token":"0123456789abcdef01234567"}`)} {
		if _, e := decodeJournal(bad); e == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	for _, mutate := range []func(*journal){func(p *journal) { p.LUID = 0 }, func(p *journal) { p.Created = -1 }, func(p *journal) { p.Index, p.LUID = 0, 0 }, func(p *journal) { p.Token = "xxxxxxxxxxxxxxxxxxxxxxxx" }} {
		bad := p
		mutate(&bad)
		b, _ := json.Marshal(bad)
		if _, e := decodeJournal(b); e == nil {
			t.Fatal("accepted invalid ownership")
		}
	}
}
