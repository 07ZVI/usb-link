package interfaceconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func bindingFixture() secondaryBinding {
	return secondaryBinding{Version: 1, OriginalSHA256: strings.Repeat("a", 64), OriginalScope: Scope{"mac", MacGUID, 4, 40}, CurrentScope: Scope{"mac", MacGUID, 4, 40}, Instance: "SWD\\WINTUN\\OWNED", State: "ready", Created: 100, Mode: "persistent"}
}
func TestSecondaryFactoryBindingTransaction(t *testing.T) {
	ready := bindingFixture()
	closed := ready
	closed.State = "closed"
	attempt := closed
	attempt.State = "attempt"
	attempt.Created = 0
	attempt.Mode = ""
	attempt.Attempt = strings.Repeat("b", 32)
	attempt.Ticks = 50
	mapped := attempt
	mapped.State = "mapped"
	mapped.CurrentScope.Index = 8
	mapped.CurrentScope.LUID = 80
	next := mapped
	next.State = "ready"
	next.Attempt = ""
	next.Ticks = 0
	next.Created = 200
	next.Mode = "persistent"
	for _, pair := range [][2]secondaryBinding{{ready, closed}, {closed, attempt}, {attempt, mapped}, {mapped, next}} {
		if e := secondaryTransition(pair[0], pair[1]); e != nil {
			t.Fatal(e)
		}
	}
	for name, pair := range map[string][2]secondaryBinding{"unknown_create_adoption": {attempt, next}, "healthy_same_guid_adoption": {ready, next}, "original_rewrite": {mapped, func() secondaryBinding { n := next; n.OriginalScope.LUID = 80; return n }()}, "foreign_instance": {attempt, func() secondaryBinding { n := mapped; n.Instance = "SWD\\FOREIGN"; return n }()}} {
		t.Run(name, func(t *testing.T) {
			if secondaryTransition(pair[0], pair[1]) == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestSecondaryBindingStrictJSON(t *testing.T) {
	v := bindingFixture()
	b, _ := json.Marshal(v)
	if _, e := decodeSecondaryBinding(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), `"version":1`, `"version":1,"version":1`, 1), strings.Replace(string(b), `"created":100,`, ``, 1), strings.Replace(string(b), `"state":"ready"`, `"state":"attempt"`, 1), strings.Replace(string(b), `"role":"mac"`, `"role":"host"`, 1)} {
		if _, e := decodeSecondaryBinding([]byte(bad)); e == nil {
			t.Fatal("accepted malformed")
		}
	}
}

func TestSecondaryBindingCannotRewriteImmutableOriginal(t *testing.T) {
	old := bindingFixture()
	original := persistentOriginal{Scope: old.OriginalScope, OriginalMTU: 1500, DesiredMTU: 1500, AddressAbsent: true, Address: "10.6.9.253", Prefix: 32, Profile: &profileOriginal{NetworkGUID: "{12345678-1234-1234-1234-123456789ABC}", Category: 0}, AppliedAddress: &addressBaseline{"forever", "forever"}}
	old.OriginalSHA256 = persistentDigest(original)
	old.CurrentScope = Scope{"mac", MacGUID, 9, 90}
	if !secondaryCurrentMatches(old, original, old.CurrentScope) {
		t.Fatal("valid separated mapping rejected")
	}
	changed := original
	changed.OriginalMTU = 16000
	if secondaryCurrentMatches(old, changed, old.CurrentScope) {
		t.Fatal("original overwritten")
	}
	old.State = "attempt"
	if secondaryCurrentMatches(old, original, old.CurrentScope) {
		t.Fatal("unknown create authorized current interface")
	}
	old.State = "closed"
	if secondaryCurrentMatches(old, original, old.CurrentScope) {
		t.Fatal("closed creator authorized active interface")
	}
}

func TestSecondaryReadyProjectionNeverAdoptsNewLUID(t *testing.T) {
	a := bindingFixture()
	b := a
	b.CurrentScope.Index++
	b.Created++
	b.Mode = "persistent"
	if secondaryTransition(a, b) != nil {
		t.Fatal("sameLUID completed projection refused")
	}
	b.CurrentScope.LUID++
	if secondaryTransition(a, b) == nil {
		t.Fatal("sameGUID newLUID adopted withoutfactory")
	}
	b = a
	b.Mode = "legacy"
	b.Created++
	if secondaryTransition(a, b) == nil {
		t.Fatal("finite Created re-adopted")
	}
}

func TestSecondaryRestoreFactoryCannotPublishReadyOrReplaceOriginal(t *testing.T) {
	closed := bindingFixture()
	closed.State = "closed"
	attempt := closed
	attempt.State, attempt.Mode, attempt.Created = "restore_attempt", "", 0
	attempt.Attempt, attempt.Ticks = strings.Repeat("b", 32), 50
	mapped := attempt
	mapped.State = "restore_mapped"
	mapped.CurrentScope.Index, mapped.CurrentScope.LUID = 8, 80
	restored := mapped
	restored.State = "restored"
	for _, pair := range [][2]secondaryBinding{{closed, attempt}, {attempt, mapped}, {mapped, restored}} {
		if secondaryTransition(pair[0], pair[1]) != nil {
			t.Fatal("strict restore phase rejected")
		}
	}
	ready := bindingFixture()
	ready.CurrentScope = mapped.CurrentScope
	for _, phase := range []secondaryBinding{attempt, mapped, restored} {
		if secondaryTransition(phase, ready) == nil || secondaryCurrentMatches(phase, persistentOriginal{}, phase.CurrentScope) {
			t.Fatal("restoring mapping became ordinary readiness")
		}
	}
	changed := restored
	changed.OriginalScope.LUID++
	if secondaryTransition(mapped, changed) == nil {
		t.Fatal("restore rewrote original ownership")
	}
	changed = restored
	changed.CurrentScope.LUID++
	if secondaryTransition(mapped, changed) == nil {
		t.Fatal("restore completion adopted another mapping")
	}
}
