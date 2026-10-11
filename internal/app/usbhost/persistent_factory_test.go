package usbhost

import (
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"testing"
)

func priorPersistentFactory() persistentFactory {
	p := priorJournal()
	p.Version = 2
	p.AddressMode = "legacy"
	p.PersistentSHA256 = strings.Repeat("a", 64)
	o := interfaceconfig.PersistentOriginalSnapshot{ImmutableScope: interfaceconfig.Scope{Role: "host", GUID: p.GUID, Index: p.Index, LUID: p.LUID}, SHA256: p.PersistentSHA256, OriginalMTU: 1500, DesiredMTU: 1500, AddressAbsent: true, Address: "10.6.9.1", Prefix: 32, NetworkGUID: "{11111111-1111-1111-1111-111111111111}", OriginalCategory: 0, AppliedValidLifetime: "4294967295", AppliedPreferredLifetime: "4294967295"}
	return persistentFactory{Original: o, Version: 1, OriginalSHA256: p.PersistentSHA256, OriginalScope: interfaceconfig.Scope{Role: "host", GUID: p.GUID, Index: p.Index, LUID: p.LUID}, JournalSHA256: journalDigestJSON(p), Source: p, Instance: `SWD\WINTUN\OWNED`, State: "ready"}
}
func factoryEncode(t *testing.T, v persistentFactory) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodePersistentFactory(b); e != nil {
		t.Fatal(e)
	}
	return b
}
func TestPersistentFactorySeparateKnownReturnAndCompleteProof(t *testing.T) {
	ready := priorPersistentFactory()
	factoryEncode(t, ready)
	closed := ready
	closed.State = "closed"
	attempt := closed
	attempt.State = "attempt"
	attempt.Attempt = strings.Repeat("b", 32)
	attempt.Ticks = 123
	mapped := attempt
	mapped.State = "mapped"
	mapped.MappedIndex = 52
	mapped.MappedLUID = 999
	proved := mapped
	proved.State = "proved"
	proved.Next = ready.Source
	proved.Next.Index = mapped.MappedIndex
	proved.Next.LUID = mapped.MappedLUID
	proved.Next.Created = 333
	proved.Next.AddressMode = "persistent"
	next := proved
	next.State = "ready"
	next.Source = proved.Next
	next.JournalSHA256 = journalDigestJSON(proved.Next)
	next.Attempt = ""
	next.Ticks = 0
	next.MappedIndex = 0
	next.MappedLUID = 0
	next.Next = journal{}
	chain := []persistentFactory{ready, closed, attempt, mapped, proved, next}
	for i, v := range chain {
		factoryEncode(t, v)
		if i > 0 && validatePersistentFactoryTransition(chain[i-1], v) != nil {
			t.Fatalf("transition %d", i)
		}
	}
	if validatePersistentFactoryTransition(attempt, next) == nil {
		t.Fatal("unknown call gained ready mapping")
	}
	if validatePersistentFactoryTransition(closed, mapped) == nil {
		t.Fatal("unknown Create bypassed intent")
	}
	if validatePersistentFactoryTransition(mapped, next) == nil {
		t.Fatal("returned DLL tuple bypassed Store/active proof")
	}
	if next.OriginalScope != ready.OriginalScope || next.OriginalSHA256 != ready.OriginalSHA256 {
		t.Fatal("factory replaced originals")
	}
}
func TestPersistentFactoryJournalCrashPositions(t *testing.T) {
	old := priorPersistentFactory()
	mapped := old
	mapped.State = "mapped"
	mapped.Attempt = strings.Repeat("c", 32)
	mapped.Ticks = 4
	mapped.MappedIndex = 41
	mapped.MappedLUID = 99
	proved := mapped
	proved.State = "proved"
	proved.Next = old.Source
	proved.Next.Index = 41
	proved.Next.LUID = 99
	proved.Next.Created = 44
	proved.Next.AddressMode = "persistent"
	b, _ := json.Marshal(old.Source)
	if next, e := persistentFactoryJournalPosition(proved, b); e != nil || next {
		t.Fatal(next, e)
	}
	b, _ = json.Marshal(proved.Next)
	if next, e := persistentFactoryJournalPosition(proved, b); e != nil || !next {
		t.Fatal(next, e)
	}
	if _, e := persistentFactoryJournalPosition(mapped, b); e == nil {
		t.Fatal("mapped raw tuple adopted unproved address journal")
	}
	foreign := proved.Next
	foreign.Created++
	b, _ = json.Marshal(foreign)
	if _, e := persistentFactoryJournalPosition(proved, b); e == nil {
		t.Fatal("changed creation accepted")
	}
	b, _ = json.Marshal(old.Source)
	b = append(b, ' ')
	if _, e := persistentFactoryJournalPosition(proved, b); e == nil {
		t.Fatal("original raw bytes changed without checkpoint")
	}
}
func TestPersistentFactorySameGUIDDoesNotPermitLUIDRebind(t *testing.T) {
	old := priorPersistentFactory()
	n := old
	n.State = "proved"
	n.Next = old.Source
	n.Next.Index++
	n.Next.Created++
	n.Next.AddressMode = "persistent"
	n.MappedIndex = n.Next.Index
	n.MappedLUID = n.Next.LUID
	if e := validatePersistentFactoryTransition(old, n); e != nil {
		t.Fatal("same LUID boot-index projection", e)
	}
	closed := old
	closed.State = "closed"
	if validatePersistentFactoryTransition(closed, n) == nil {
		t.Fatal("pending creator Close reopened transient healthy result")
	}
	n.Next.LUID++
	n.MappedLUID = n.Next.LUID
	if validatePersistentFactoryTransition(old, n) == nil {
		t.Fatal("same GUID foreign LUID adopted without mapped factory")
	}
	n = old
	n.State = "closed"
	n.OriginalSHA256 = strings.Repeat("b", 64)
	if validatePersistentFactoryTransition(old, n) == nil {
		t.Fatal("original replaced")
	}
}
func TestPersistentFactoryStrictNestedRecords(t *testing.T) {
	good := string(factoryEncode(t, priorPersistentFactory()))
	cases := []string{strings.Replace(good, `"Version":1`, `"Version":1,"Version":1`, 1), strings.Replace(good, `"Source":{`, `"Source":{"Version":2,`, 1), strings.Replace(good, `"role":"host"`, `"role":"host","role":"host"`, 1), strings.Replace(good, `"Version":1,`, "", 1), good + "{}", strings.Replace(good, `"State":"ready"`, `"State":"attempt"`, 1)}
	for _, b := range cases {
		if _, e := decodePersistentFactory([]byte(b)); e == nil {
			t.Fatalf("invalid record accepted %s", b)
		}
	}
}

func TestPersistentFactoryUnknownCallsNeedRebootAndCompleteAbsence(t *testing.T) {
	v := priorPersistentFactory()
	v.State = "attempt"
	v.Attempt = strings.Repeat("d", 32)
	v.Ticks = 100
	if persistentFactoryUnknownAbsent(v, 50, true, 0, 0) != nil {
		t.Fatal("exact reboot/absence fenced")
	}
	for _, x := range []struct {
		ticks    uint64
		absent   bool
		old, new int
	}{{0, true, 0, 0}, {100, true, 0, 0}, {200, true, 0, 0}, {50, false, 0, 0}, {50, true, 1, 0}, {50, true, 0, 1}} {
		if persistentFactoryUnknownAbsent(v, x.ticks, x.absent, x.old, x.new) == nil {
			t.Fatal("unknown call promoted", x)
		}
	}
	v.State = "ready"
	if persistentFactoryUnknownAbsent(v, 50, true, 0, 0) == nil {
		t.Fatal("generic ready treated as unknown call")
	}
}
func TestPersistentFactoryUninstallNeverConvertsToLegacyCreate(t *testing.T) {
	old := priorPersistentFactory()
	restoring := old
	restoring.State = "restoring"
	stopped := restoring
	stopped.State = "stopped"
	removing := stopped
	removing.State = "removing"
	removing.Attempt = strings.Repeat("e", 32)
	removing.Ticks = 10
	unknown := removing
	unknown.State = "removal_unknown"
	removed := unknown
	removed.State = "removed"
	chain := []persistentFactory{old, restoring, stopped, removing, unknown, removed}
	for i, v := range chain {
		factoryEncode(t, v)
		if i > 0 && validatePersistentFactoryTransition(chain[i-1], v) != nil {
			t.Fatalf("restore %d", i)
		}
	}
	if validatePersistentFactoryTransition(restoring, removing) == nil {
		t.Fatal("unproved originals bypassed stopped")
	}
	if validatePersistentFactoryTransition(unknown, old) == nil {
		t.Fatal("unknown DIF became ready")
	}
	for _, v := range chain {
		if v.Source.Version != 2 || v.Original != old.Original || v.Source != old.Source {
			t.Fatal("uninstall rewrote original/journal")
		}
	}
	changed := removed
	changed.Attempt = strings.Repeat("f", 32)
	if validatePersistentFactoryTransition(unknown, changed) == nil {
		t.Fatal("DIF nonce replaced")
	}
}
func TestPersistentFactoryOriginalAndProvedNestedAmbiguityRejected(t *testing.T) {
	v := priorPersistentFactory()
	good := string(factoryEncode(t, v))
	bad := strings.Replace(good, `"OriginalMTU":1500`, `"OriginalMTU":1500,"OriginalMTU":1500`, 1)
	if _, e := decodePersistentFactory([]byte(bad)); e == nil {
		t.Fatal("ambiguous original")
	}
	v.State = "proved"
	v.Next = v.Source
	v.Next.Index++
	v.MappedIndex = v.Next.Index
	v.MappedLUID = v.Next.LUID
	good = string(factoryEncode(t, v))
	start := strings.Index(good, `"Next":`)
	bad = good[:start] + strings.Replace(good[start:], `"Created":`, `"Created":3,"Created":`, 1)
	if _, e := decodePersistentFactory([]byte(bad)); e == nil {
		t.Fatal("ambiguous next creation")
	}
}

func TestPersistentFactoryFinalTwoFileDeletionCrashFence(t *testing.T) {
	v := priorPersistentFactory()
	v.State = "removed"
	v.Attempt = strings.Repeat("f", 32)
	v.Ticks = 9
	b, _ := json.Marshal(v.Source)
	if persistentFactoryFinalJournalGate(v, b, true) != nil || persistentFactoryFinalJournalGate(v, nil, false) != nil {
		t.Fatal("known confirmed removal crash position rejected")
	}
	bad := v
	bad.State = "removal_unknown"
	if persistentFactoryFinalJournalGate(bad, nil, false) == nil {
		t.Fatal("unknown removal lost journal")
	}
	bad = v
	bad.Source.Created++
	if persistentFactoryFinalJournalGate(bad, b, true) == nil {
		t.Fatal("foreign journal removed")
	}
}

func TestPersistentFactoryKnownMappedIndexProjectionKeepsReturnedLUID(t *testing.T) {
	old := priorPersistentFactory()
	old.State = "mapped"
	old.Attempt = strings.Repeat("a", 32)
	old.Ticks = 200
	old.MappedIndex = 23
	old.MappedLUID = 1234
	projected := old
	projected.MappedIndex = 24
	if validatePersistentFactoryTransition(old, projected) != nil {
		t.Fatal("same returned LUID boot index rejected")
	}
	foreign := projected
	foreign.MappedLUID++
	if validatePersistentFactoryTransition(old, foreign) == nil {
		t.Fatal("foreign returned LUID adopted")
	}
	changed := projected
	changed.Source.Index++
	if validatePersistentFactoryTransition(old, changed) == nil {
		t.Fatal("old protected source rewritten by projection")
	}
}
func TestPersistentFactoryTimingsExposeFixedNamesOnly(t *testing.T) {
	before := PersistentHostFactoryTimingsSnapshot()
	persistentFactoryPhase("private path or identifier")(nil)
	after := PersistentHostFactoryTimingsSnapshot()
	if len(before) != len(after) {
		t.Fatal("arbitrary diagnostic label retained")
	}
}

func TestRestoreOnlyFactoryNeverPublishesNetworkOwnership(t *testing.T) {
	old := priorPersistentFactory()
	attempt := old
	attempt.State = "restore_attempt"
	attempt.Attempt = strings.Repeat("d", 32)
	attempt.Ticks = 987
	mapped := attempt
	mapped.State = "restore_mapped"
	mapped.MappedIndex = 71
	mapped.MappedLUID = 9999
	stopped := mapped
	stopped.State = "restore_stopped"
	removing := stopped
	removing.State = "restore_removing"
	removing.Attempt = strings.Repeat("e", 32)
	removing.Ticks = 999
	unknown := removing
	unknown.State = "restore_removal_unknown"
	removed := unknown
	removed.State = "restore_removed"
	chain := []persistentFactory{old, attempt, mapped, stopped, removing, unknown, removed}
	for i, v := range chain {
		factoryEncode(t, v)
		if i > 0 && validatePersistentFactoryTransition(chain[i-1], v) != nil {
			t.Fatalf("restore step %d rejected", i)
		}
		if v.Source != old.Source || v.JournalSHA256 != old.JournalSHA256 || v.Original != old.Original {
			t.Fatal("restore-only replaced immutable ownership")
		}
		if i > 0 && validatePersistentFactoryTransition(v, old) == nil {
			t.Fatal("restore-only published Ready")
		}
	}
	proved := mapped
	proved.State = "proved"
	proved.Next = old.Source
	proved.Next.Index = mapped.MappedIndex
	proved.Next.LUID = mapped.MappedLUID
	if validatePersistentFactoryTransition(mapped, proved) == nil {
		t.Fatal("restore return became a network proof")
	}
	ordinaryMapped := mapped
	ordinaryMapped.State = "mapped"
	if validatePersistentFactoryTransition(attempt, ordinaryMapped) == nil {
		t.Fatal("uninstall creator entered ordinary network path")
	}
	if validatePersistentFactoryTransition(attempt, stopped) == nil || validatePersistentFactoryTransition(mapped, removing) == nil {
		t.Fatal("restore intent skipped observed return or original-value gate")
	}
	wrong := stopped
	wrong.MappedLUID++
	if validatePersistentFactoryTransition(mapped, wrong) == nil {
		t.Fatal("restore adopted foreign mapping")
	}
	wrong = removed
	wrong.MappedIndex++
	if validatePersistentFactoryTransition(unknown, wrong) == nil {
		t.Fatal("unknown removal changed returned mapping")
	}
}

func TestRestoreOnlyFactoryReplayRequiresRestartAndBothAbsences(t *testing.T) {
	v := priorPersistentFactory()
	v.State = "restore_attempt"
	v.Attempt = strings.Repeat("c", 32)
	v.Ticks = 500
	if persistentFactoryUnknownAbsent(v, 501, true, 0, 0) == nil {
		t.Fatal("same-boot unknown creator was retried")
	}
	if persistentFactoryUnknownAbsent(v, 50, false, 0, 0) == nil {
		t.Fatal("unknown creator adopted installed node")
	}
	v.State = "restore_mapped"
	v.MappedIndex = 99
	v.MappedLUID = 999
	for _, rows := range [][2]int{{1, 0}, {0, 1}} {
		if persistentFactoryUnknownAbsent(v, 50, true, rows[0], rows[1]) == nil {
			t.Fatal("restore dropped old or returned mapping address")
		}
	}
	if e := persistentFactoryUnknownAbsent(v, 50, true, 0, 0); e != nil {
		t.Fatal(e)
	}
	closed := v
	closed.State = "closed"
	closed.Attempt = ""
	closed.Ticks = 0
	closed.MappedIndex = 0
	closed.MappedLUID = 0
	if validatePersistentFactoryTransition(v, closed) != nil {
		t.Fatal("bounded absence retry rejected")
	}
	mapped := v
	mapped.MappedIndex++
	if validatePersistentFactoryTransition(v, mapped) != nil {
		t.Fatal("same returned LUID index projection rejected")
	}
	mapped.MappedLUID++
	if validatePersistentFactoryTransition(v, mapped) == nil {
		t.Fatal("foreign LUID projection accepted")
	}
}

func TestRestoreOnlyRemovedKeepsOriginalJournalThroughFinalCheckpoint(t *testing.T) {
	v := priorPersistentFactory()
	v.State = "restore_removed"
	v.Attempt = strings.Repeat("c", 32)
	v.Ticks = 8
	v.MappedIndex = 70
	v.MappedLUID = 900
	b, _ := json.Marshal(v.Source)
	if persistentFactoryFinalJournalGate(v, b, true) != nil || persistentFactoryFinalJournalGate(v, nil, false) != nil {
		t.Fatal("exact removed journal or interrupted deletion rejected")
	}
	if factoryRemovalLUID(v) != 900 || factoryRemovalPhase(v, "removed") != "restore_removed" {
		t.Fatal("cleanup reverted to old mapping")
	}
	foreign := v.Source
	foreign.LUID = v.MappedLUID
	foreign.Index = v.MappedIndex
	b, _ = json.Marshal(foreign)
	if persistentFactoryFinalJournalGate(v, b, true) == nil {
		t.Fatal("restore-only overwrote original journal with returned map")
	}
	v.State = "restore_removing"
	if persistentFactoryFinalJournalGate(v, nil, false) == nil {
		t.Fatal("unknown removal erased source journal")
	}
}

func TestRestoreOnlyFactoryKeepsDomainAndUnknownTupleFences(t *testing.T) {
	v := priorPersistentFactory()
	v.State = "restore_mapped"
	v.Attempt = strings.Repeat("c", 32)
	v.Ticks = 5
	v.MappedIndex = 9
	v.MappedLUID = 99
	for _, phase := range []string{"restore_mapped", "restore_stopped", "restore_removing", "restore_removed", "restore_removal_unknown", "restore_removal_restart"} {
		current := v
		current.State = phase
		for _, mutate := range []func(*persistentFactory){func(p *persistentFactory) { p.MappedIndex = 0 }, func(p *persistentFactory) { p.MappedLUID = 0 }, func(p *persistentFactory) { p.Ticks = 0 }, func(p *persistentFactory) { p.Attempt = "" }} {
			broken := current
			mutate(&broken)
			if validatePersistentFactory(broken) == nil {
				t.Fatalf("%s accepted incomplete actual return", phase)
			}
		}
	}
	v.Original.OriginalCategory = 2
	b, _ := json.Marshal(v)
	if _, e := decodePersistentFactory(b); e == nil {
		t.Fatal("restore blind-adopted domain authenticated profile")
	}
}
