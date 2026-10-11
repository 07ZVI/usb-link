package usbhost

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func recreateFixture() (journal, []byte, recreateTransaction) {
	p := journal{Version: 1, GUID: usbaddress.HostGUID, Index: 23, LUID: 11, Planned: 100, Created: 120, Token: strings.Repeat("0", 24)}
	b, _ := json.Marshal(p)
	t := recreateTransaction{Version: 1, OldSHA256: journalDigest(b), OriginalLUID: p.LUID, Instance: `SWD\WINTUN\{ABC}`, Token: strings.Repeat("1", 24), Ticks: 10000, State: "attempt"}
	return p, b, t
}

func mappedRecreate(t recreateTransaction) recreateTransaction {
	t.State = "mapped"
	t.Next = journal{Version: 1, GUID: usbaddress.HostGUID, Index: 24, LUID: 22, Planned: 200, Token: t.Token}
	return t
}
func readyRecreate(t recreateTransaction) recreateTransaction {
	t = mappedRecreate(t)
	t.State = "ready"
	t.Next.Created = 210
	return t
}

func TestRecreateJournalRejectsAmbiguityBeforeNativeCall(t *testing.T) {
	p, raw, _ := recreateFixture()
	if got, e := decodeRecreateJournal(raw); e != nil || got != p {
		t.Fatal("complete journal rejected", e)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"Created":120`), []byte(`"Created":1,"Created":120`), 1),
		bytes.Replace(raw, []byte(`"Token":"`), []byte(`"unknown":0,"Token":"`), 1),
		bytes.Replace(raw, []byte(`"Index":23,`), nil, 1),
		append(append([]byte{}, raw...), []byte(` {}`)...),
		bytes.Repeat([]byte(" "), 2049),
	} {
		if _, e := decodeRecreateJournal(bad); e == nil {
			t.Fatal("ambiguous old journal accepted", string(bad))
		}
	}
	b, e := os.ReadFile("recreate_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	start := strings.Index(string(b), "func readRecreateJournal(")
	if start < 0 {
		t.Fatal("protected reader missing")
	}
	end := strings.Index(string(b)[start:], "func recordRecreate(")
	if end < 0 || !strings.Contains(string(b)[start:start+end], "decodeRecreateJournal(b)") {
		t.Fatal("protected reader can bypass strict original journal parsing")
	}
}

func TestRecreateStrictReceiptRejectsMalformedAndDuplicateInput(t *testing.T) {
	_, _, base := recreateFixture()
	for _, stage := range []recreateTransaction{base, mappedRecreate(base), readyRecreate(base), func() recreateTransaction { x := base; x.State = "closing"; return x }()} {
		raw, _ := json.Marshal(stage)
		if got, e := decodeRecreateTransaction(raw); e != nil || got != stage {
			t.Fatalf("valid %s rejected: %v", stage.State, e)
		}
		for _, bad := range [][]byte{
			append(append([]byte{}, raw...), []byte(` {}`)...),
			bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
			bytes.Replace(raw, []byte(`"next":{`), []byte(`"unknown":true,"next":{`), 1),
			bytes.Replace(raw, []byte(`"Version":1`), []byte(`"Version":1,"Version":1`), 1),
			bytes.Replace(raw, []byte(`"Version":0`), []byte(`"Version":0,"Version":0`), 1),
			bytes.Replace(raw, []byte(`"original_luid":11,`), nil, 1),
		} {
			if bytes.Equal(bad, raw) {
				continue
			}
			if _, e := decodeRecreateTransaction(bad); e == nil {
				t.Fatalf("accepted malformed %s", bad)
			}
		}
	}
	changes := []func(*recreateTransaction){
		func(x *recreateTransaction) { x.Version = 2 }, func(x *recreateTransaction) { x.OriginalLUID = 0 }, func(x *recreateTransaction) { x.Ticks = 0 },
		func(x *recreateTransaction) { x.OldSHA256 = strings.Repeat("z", 64) }, func(x *recreateTransaction) { x.Token = strings.Repeat("z", 24) },
		func(x *recreateTransaction) { x.Instance = "" }, func(x *recreateTransaction) { x.Instance = "SWD*" }, func(x *recreateTransaction) { x.Instance = "SWD\x00" },
		func(x *recreateTransaction) { x.Instance = strings.Repeat("a", 1025) }, func(x *recreateTransaction) { x.State = "adopt" },
		func(x *recreateTransaction) { x.Next = mappedRecreate(*x).Next },
	}
	for _, change := range changes {
		x := base
		change(&x)
		raw, _ := json.Marshal(x)
		if _, e := decodeRecreateTransaction(raw); e == nil {
			t.Fatalf("accepted invalid %+v", x)
		}
	}
	if _, e := decodeRecreateTransaction(bytes.Repeat([]byte(" "), 4097)); e == nil {
		t.Fatal("unbounded receipt accepted")
	}
	ready := readyRecreate(base)
	for _, change := range []func(*recreateTransaction){func(x *recreateTransaction) { x.Next.Token = strings.Repeat("0", 24) }, func(x *recreateTransaction) { x.Next.LUID = 0 }, func(x *recreateTransaction) { x.Next.Created = x.Next.Planned - 1 }, func(x *recreateTransaction) { x.Next.Created = x.Next.Planned + 150000001 }} {
		x := ready
		change(&x)
		raw, _ := json.Marshal(x)
		if _, e := decodeRecreateTransaction(raw); e == nil {
			t.Fatalf("unproven ready accepted %+v", x)
		}
	}
}

func TestRecreateReplayCannotAdoptOrChangeOwnership(t *testing.T) {
	_, old, attempt := recreateFixture()
	mapped := mappedRecreate(attempt)
	ready := readyRecreate(attempt)
	newBytes, _ := json.Marshal(ready.Next)
	for _, stage := range []recreateTransaction{attempt, mapped, ready} {
		if pos, e := recreateJournalPosition(stage, old); e != nil || pos != "old" {
			t.Fatal(stage.State, pos, e)
		}
		pos, e := recreateJournalPosition(stage, newBytes)
		if stage.State == "ready" {
			if e != nil || pos != "new" {
				t.Fatal(pos, e)
			}
		} else if e == nil {
			t.Fatal("unknown creation adopted completed replacement", stage.State)
		}
	}
	foreign := ready.Next
	foreign.Token = attempt.Token[:22] + "ff"
	raw, _ := json.Marshal(foreign)
	if _, e := recreateJournalPosition(ready, raw); e == nil {
		t.Fatal("foreign completed receipt adopted")
	}
	duplicate := bytes.Replace(newBytes, []byte(`"Created":210`), []byte(`"Created":1,"Created":210`), 1)
	if _, e := recreateJournalPosition(ready, duplicate); e == nil {
		t.Fatal("ambiguous journal accepted")
	}
	for _, ticks := range []uint64{0, 10000, 10001, 999999999} {
		if recreateUnknownRecoveryGate(attempt, ticks) == nil {
			t.Fatal("elapsed time released unknown call", ticks)
		}
	}
	if e := recreateUnknownRecoveryGate(attempt, 9999); e != nil {
		t.Fatal("counter reset rejected", e)
	}
}

func TestRecreateTransitionsRetainOriginalReceiptAndReturnedMapping(t *testing.T) {
	_, _, attempt := recreateFixture()
	mapped := mappedRecreate(attempt)
	ready := readyRecreate(attempt)
	if e := validateRecreateTransition(attempt, mapped); e != nil {
		t.Fatal(e)
	}
	if e := validateRecreateTransition(mapped, ready); e != nil {
		t.Fatal(e)
	}
	closing := ready
	closing.State = "closing"
	raw, _ := json.Marshal(ready.Next)
	closing.OldSHA256 = journalDigest(raw)
	closing.OriginalLUID = ready.Next.LUID
	closing.Next = journal{}
	if e := validateRecreateTransition(ready, closing); e != nil {
		t.Fatal("ready replay cannot safely retire", e)
	}
	for _, pair := range [][2]recreateTransaction{{attempt, ready}, {mapped, attempt}, {ready, mapped}, {closing, attempt}, {attempt, closing}} {
		if validateRecreateTransition(pair[0], pair[1]) == nil {
			t.Fatalf("phase skipped/replayed: %s -> %s", pair[0].State, pair[1].State)
		}
	}
	for _, change := range []func(*recreateTransaction){func(x *recreateTransaction) { x.OldSHA256 = strings.Repeat("a", 64) }, func(x *recreateTransaction) { x.Instance += "X" }, func(x *recreateTransaction) { x.OriginalLUID++ }, func(x *recreateTransaction) { x.Ticks++ }, func(x *recreateTransaction) { x.Token = strings.Repeat("f", 24) }, func(x *recreateTransaction) { x.Next.Index++ }, func(x *recreateTransaction) { x.Next.LUID++ }, func(x *recreateTransaction) { x.Next.Planned++ }} {
		x := ready
		change(&x)
		if validateRecreateTransition(mapped, x) == nil {
			t.Fatal("ownership/mapping changed during ready", x)
		}
	}
	x := closing
	x.OldSHA256 = attempt.OldSHA256
	if validateRecreateTransition(ready, x) == nil {
		t.Fatal("replay closing still bound to old receipt")
	}
}

func TestClosingAddressScopeUsesCurrentIndexButOriginalLUIDAndStamp(t *testing.T) {
	p, _, _ := recreateFixture()
	a := recoveryAddress{Index: 24, LUID: p.LUID, Address: [4]byte{10, 6, 9, 1}, Prefix: 32, PrefixOrigin: 1, SuffixOrigin: 1, ValidLifetime: 3600, PreferredLifetime: 3600, Created: p.Created}
	for _, rows := range [][]recoveryAddress{nil, {a}} {
		next, _, e := rebindClosing(p, 24, p.LUID, rows)
		if e != nil || next.Index != 24 || next.Created != p.Created || next.Token != p.Token {
			t.Fatal(next, e)
		}
	}
	if _, _, e := rebindClosing(p, 24, p.LUID+1, nil); e == nil {
		t.Fatal("changed LUID authorized cleanup")
	}
	for _, change := range []func(*recoveryAddress){func(x *recoveryAddress) { x.Created++ }, func(x *recoveryAddress) { x.Address = [4]byte{10, 6, 10, 1} }, func(x *recoveryAddress) { x.Prefix = 24 }, func(x *recoveryAddress) { x.PrefixOrigin = 0 }, func(x *recoveryAddress) { x.SuffixOrigin = 0 }, func(x *recoveryAddress) { x.ValidLifetime++ }, func(x *recoveryAddress) { x.Index = 23 }} {
		x := a
		change(&x)
		if _, _, e := rebindClosing(p, 24, p.LUID, []recoveryAddress{x}); e == nil {
			t.Fatal("foreign/untyped row authorized", x)
		}
	}
	if _, _, e := rebindClosing(p, 24, p.LUID, []recoveryAddress{a, a}); e == nil {
		t.Fatal("extra address authorized cleanup")
	}
}

// These negative scope contracts supplement the replay tests; they do not
// claim execution of Windows SetupAPI, ACLs, Wintun or real PnP retirement.
func TestRecreateLifecycleHasNoActiveDIFOrDetachedNativeCall(t *testing.T) {
	for _, name := range []string{"recreate_windows.go", "../../platform/windows/netconfig/host_recreate_native_windows.go"} {
		b, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		s := string(b)
		for _, forbidden := range []string{"CallClassInstaller(", "RemoveVerifiedSharedHostNative(", "RemoveVerifiedNonpresentSharedHostNative(", "netconfig.Run(", "go wintun.", "go func()"} {
			if strings.Contains(s, forbidden) {
				t.Fatal("creation/closing gained destructive or detached scope", name, forbidden)
			}
		}
	}
	b, e := os.ReadFile("../../transport/wintun/device_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	pre := strings.Index(s, "if beforeCreate != nil {")
	call := strings.Index(s, "d.adapter, _, err = create.Call(")
	if pre < 0 || call < pre || strings.Contains(s[pre:call], ".Call(") || strings.Contains(s, "go func()") {
		t.Fatal("proof is no longer adjacent to synchronous Create")
	}
}

func TestRecreateAbsentAddressCheckDoesNotUseHistoricalIndex(t *testing.T) {
	// Host index 23 has vanished and another adapter now owns that index. Only
	// the saved LUID is relevant when complete installed/MIB absence is proven.
	if recoveryAddressMatches(0, 11, 23, 99) || recoveryAddressMatches(0, 11, 0, 99) {
		t.Fatal("historical/zero index selected a foreign adapter")
	}
	if !recoveryAddressMatches(0, 11, 24, 11) {
		t.Fatal("dangling address with exact saved LUID was missed")
	}
	// A current verified interface keeps the stricter union; index/LUID
	// mismatch remains visible to ownership validation, rather than discarded.
	if !recoveryAddressMatches(24, 11, 24, 99) || !recoveryAddressMatches(24, 11, 99, 11) {
		t.Fatal("current mapping conflict was hidden")
	}
}
