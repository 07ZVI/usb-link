package appfirewall

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type memoryDisk struct {
	state  Store
	saves  int
	failAt int
}

func cloneStore(s Store) Store {
	b, _ := json.Marshal(s)
	var out Store
	_ = json.Unmarshal(b, &out)
	return out
}
func (d *memoryDisk) Load() (Store, error) { return cloneStore(d.state), nil }
func (d *memoryDisk) Save(s Store) error {
	d.saves++
	if d.saves == d.failAt {
		return errors.New("disk unavailable")
	}
	d.state = cloneStore(s)
	return nil
}

type fakeExecutor struct {
	disk     *memoryDisk
	fail     bool
	identity Identity
	changes  []Change
	t        *testing.T
}

func (e *fakeExecutor) Inspect(context.Context, string) (Identity, error) { return e.identity, nil }
func (e *fakeExecutor) Apply(_ context.Context, c Change) error {
	if e.disk.state.Pending == nil {
		e.t.Fatal("OS change without durable intent")
	}
	e.changes = append(e.changes, c)
	if e.fail {
		return errors.New("provider failed")
	}
	return nil
}
func sampleRule() Rule {
	return Rule{ID: strings.Repeat("a", 32), Application: Identity{Path: `C:\Programs\sample.exe`, SHA256: strings.Repeat("1", 64), Size: 4096}, Action: "block", Direction: "outbound", Protocol: "tcp", Remote: "any", Port: 443, State: "pending"}
}
func setup(t *testing.T) (*Manager, *memoryDisk, *fakeExecutor) {
	t.Helper()
	d := &memoryDisk{state: Store{Version: 1, Rules: []Rule{}}}
	e := &fakeExecutor{disk: d, t: t, identity: sampleRule().Application}
	m, err := New(context.Background(), d, e)
	if err != nil {
		t.Fatal(err)
	}
	return m, d, e
}

func TestRuleLifecycleDurableIntentAndExactRemoval(t *testing.T) {
	m, d, e := setup(t)
	r := sampleRule()
	r.ID = ""
	if err := m.Upsert(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	rules, p := m.Snapshot()
	if p != "" || len(rules) != 1 || rules[0].State != "applied" || d.state.Pending != nil || len(e.changes) != 1 {
		t.Fatal(rules, p)
	}
	id := rules[0].ID
	r = rules[0]
	r.Application.Path = `C:\evil.exe`
	r.Action = "allow"
	if err := m.Upsert(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if e.changes[1].Rule.Application.Path != sampleRule().Application.Path {
		t.Fatal("UI replaced owned application")
	}
	if err := m.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	rules, _ = m.Snapshot()
	if len(rules) != 0 || len(e.changes) != 3 || e.changes[2].Operation != "delete" {
		t.Fatal("deletion failed")
	}
}
func TestIntentSaveFailureNeverMutatesOS(t *testing.T) {
	m, d, e := setup(t)
	d.failAt = 1
	r := sampleRule()
	r.ID = ""
	if m.Upsert(context.Background(), r) == nil || len(e.changes) != 0 || d.state.Pending != nil {
		t.Fatal("OS changed despite unsaved intent")
	}
}
func TestProviderFailureSurvivesRestartAndRecovers(t *testing.T) {
	m, d, e := setup(t)
	e.fail = true
	r := sampleRule()
	r.ID = ""
	if m.Upsert(context.Background(), r) == nil || d.state.Pending == nil {
		t.Fatal("missing recovery receipt")
	}
	rules, p := m.Snapshot()
	if len(rules) != 1 || rules[0].State != "pending" || p == "" {
		t.Fatal(rules, p)
	}
	restarted, err := New(context.Background(), d, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, p = restarted.Snapshot(); p == "" {
		t.Fatal("failed recovery hidden")
	}
	e.fail = false
	restarted, err = New(context.Background(), d, e)
	if err != nil {
		t.Fatal(err)
	}
	rules, p = restarted.Snapshot()
	if p != "" || len(rules) != 1 || rules[0].State != "applied" || d.state.Pending != nil {
		t.Fatal("recovery failed")
	}
}
func TestCompletionSaveFailureRetainsReceipt(t *testing.T) {
	m, d, e := setup(t)
	d.failAt = 2
	r := sampleRule()
	r.ID = ""
	if m.Upsert(context.Background(), r) == nil || d.state.Pending == nil || len(e.changes) != 1 {
		t.Fatal("lost commit recovery")
	}
	d.failAt = 0
	m, err := New(context.Background(), d, e)
	if err != nil {
		t.Fatal(err)
	}
	rul, p := m.Snapshot()
	if len(rul) != 1 || p != "" || d.state.Pending != nil {
		t.Fatal("failed replay")
	}
}
func TestChangedBinaryRequiresNewReview(t *testing.T) {
	m, _, e := setup(t)
	r := sampleRule()
	r.ID = ""
	if err := m.Upsert(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	rules, _ := m.Snapshot()
	e.identity.SHA256 = strings.Repeat("2", 64)
	if err := m.Upsert(context.Background(), rules[0]); err == nil || !strings.Contains(err.Error(), "APPLICATION_CHANGED") || len(e.changes) != 1 {
		t.Fatal("changed binary silently accepted", err)
	}
}
func TestDiscardAndUninstallOnlyReceiptRules(t *testing.T) {
	m, d, e := setup(t)
	r := sampleRule()
	r.ID = ""
	e.fail = true
	_ = m.Upsert(context.Background(), r)
	id := d.state.Pending.Rule.ID
	e.fail = false
	if err := m.DiscardPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.changes[len(e.changes)-1].Operation != "delete" || e.changes[len(e.changes)-1].Rule.ID != id || d.state.Pending != nil {
		t.Fatal("wrong pending removal")
	}
	_ = m.Upsert(context.Background(), r)
	_ = m.Upsert(context.Background(), r)
	if err := m.RemoveAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(d.state.Rules) != 0 {
		t.Fatal("uninstall did not remove rules")
	}
}
func TestInvalidIDsNeverCallExecutor(t *testing.T) {
	m, _, e := setup(t)
	if m.Delete(context.Background(), "all") == nil {
		t.Fatal("invalid delete")
	}
	r := sampleRule()
	if m.Upsert(context.Background(), r) == nil || len(e.changes) != 0 {
		t.Fatal("unknown id write")
	}
}
func TestInvalidStoreRejectedBeforeOS(t *testing.T) {
	_, d, e := setup(t)
	d.state.Pending = &Change{Operation: "shell", Rule: sampleRule()}
	if _, err := New(context.Background(), d, e); err == nil || len(e.changes) != 0 {
		t.Fatal("invalid receipt executed")
	}
}

type auditingExecutor struct {
	*fakeExecutor
	fn func([]Rule) ([]Rule, error)
}

func (e auditingExecutor) Audit(_ context.Context, r []Rule) ([]Rule, error) { return e.fn(r) }
func TestRefreshNeverUsesStaleSuccessfulEvidence(t *testing.T) {
	for _, mode := range []string{"provider-error", "invalid-reply", "changed-intent", "externally-removed"} {
		t.Run(mode, func(t *testing.T) {
			m, d, e := setup(t)
			r := sampleRule()
			r.ID = ""
			if err := m.Upsert(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			beforeSaves := d.saves
			m.executor = auditingExecutor{fakeExecutor: e, fn: func(rows []Rule) ([]Rule, error) {
				switch mode {
				case "provider-error":
					return nil, errors.New("query failed")
				case "invalid-reply":
					return nil, nil
				case "changed-intent":
					rows[0].Action = "allow"
				case "externally-removed":
					rows[0].State = "error"
					rows[0].Error = "FIREWALL_RULE_NOT_EFFECTIVE"
				}
				return rows, nil
			}}
			err := m.Audit(context.Background())
			if mode != "externally-removed" && err == nil {
				t.Fatal("invalid evidence accepted")
			}
			rows, _ := m.Snapshot()
			if rows[0].State != "error" || rows[0].Error == "" || rows[0].Action != "block" {
				t.Fatal("stale or changed receipt displayed", rows)
			}
			if d.saves != beforeSaves || len(e.changes) != 1 {
				t.Fatal("read-only refresh mutated system or receipt")
			}
		})
	}
}
func TestRuleValidation(t *testing.T) {
	for _, change := range []func(*Rule){func(r *Rule) { r.Application.Path = `\\server\bad.exe` }, func(r *Rule) { r.Application.Path = `C:\x\..\bad.exe` }, func(r *Rule) { r.Application.Path = `C:\x.exe:evil.exe` }, func(r *Rule) { r.Application.Path = "C:\\bad\n.exe" }, func(r *Rule) { r.Protocol = "any" }, func(r *Rule) { r.Remote = "example.com" }, func(r *Rule) { r.Direction = "both" }, func(r *Rule) { r.Application.SHA256 = "bad" }, func(r *Rule) { r.Application.Size = 0 }} {
		r := sampleRule()
		change(&r)
		if r.Valid() {
			t.Fatal("invalid rule accepted", r)
		}
	}
	r := sampleRule()
	r.Application.Path = `C:\Program Files\a'$(code).exe`
	if !r.Valid() {
		t.Fatal("safe literal path rejected")
	}
}
