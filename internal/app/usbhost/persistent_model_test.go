package usbhost

import (
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"testing"
)

func stablePersistentProof(mode string) interfaceconfig.ActiveOwnership {
	return interfaceconfig.ActiveOwnership{Scope: interfaceconfig.Scope{Role: "host", GUID: priorJournal().GUID, Index: 31, LUID: priorJournal().LUID}, Created: 210, ReceiptSHA256: strings.Repeat("a", 64), AddressMode: mode}
}
func TestPersistentJournalRequiresFullStableDistinctContract(t *testing.T) {
	old := priorJournal()
	proof := stablePersistentProof("persistent")
	next, e := planPersistentHostMapping(old, proof, proof)
	if e != nil || next.Version != 2 || next.Created != 210 || next.Token != old.Token {
		t.Fatal(next, e)
	}
	foreign := proof
	foreign.Scope.LUID++
	if _, e := planPersistentHostMapping(old, foreign, foreign); e == nil {
		t.Fatal("factory LUID adopted without held Create transaction")
	}
	b, _ := json.Marshal(next)
	if _, e := decodeJournal(b); e != nil {
		t.Fatal(e)
	}
	if _, e := decodeRecreateJournal(b); e != nil {
		t.Fatal("strict creation journal could not preserve v2 originals", e)
	}
	for _, mutate := range []func(*interfaceconfig.ActiveOwnership){func(a *interfaceconfig.ActiveOwnership) { a.Created++ }, func(a *interfaceconfig.ActiveOwnership) { a.Scope.GUID = interfaceconfig.MacGUID }, func(a *interfaceconfig.ActiveOwnership) { a.Scope.LUID++ }, func(a *interfaceconfig.ActiveOwnership) { a.AddressMode = "legacy" }, func(a *interfaceconfig.ActiveOwnership) { a.ReceiptSHA256 = strings.Repeat("b", 64) }} {
		bad := proof
		mutate(&bad)
		if _, e := planPersistentHostMapping(next, proof, bad); e == nil {
			t.Fatal("changed proof admitted")
		}
	}
	legacy := proof
	legacy.AddressMode = "legacy"
	legacy.Created = old.Created
	if _, e := planPersistentHostMapping(old, legacy, legacy); e != nil {
		t.Fatal("same session finite address", e)
	}
	legacy.Created++
	if _, e := planPersistentHostMapping(old, legacy, legacy); e == nil {
		t.Fatal("finite Created re-adoption")
	}
}
func TestV2PersistentJournalRejectsIncompleteOrLegacyFlagForgery(t *testing.T) {
	old := priorJournal()
	proof := stablePersistentProof("persistent")
	good, _ := planPersistentHostMapping(old, proof, proof)
	for _, mutate := range []func(*journal){func(p *journal) { p.Version = 1 }, func(p *journal) { p.Created = 0 }, func(p *journal) { p.AddressMode = "" }, func(p *journal) { p.AddressMode = "any" }, func(p *journal) { p.PersistentSHA256 = "" }, func(p *journal) { p.PersistentSHA256 = strings.Repeat("z", 64) }} {
		p := good
		mutate(&p)
		b, _ := json.Marshal(p)
		if _, e := decodeJournal(b); e == nil {
			t.Fatal("invalid persistent ownership admitted", p)
		}
	}
	b, _ := json.Marshal(good)
	b = []byte(strings.Replace(string(b), `"Version":2`, `"Version":2,"Version":2`, 1))
	if _, e := decodeJournal(b); e == nil {
		t.Fatal("ambiguous v2 journal")
	}
}
