//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type photoPolicyFake struct {
	mu                                sync.Mutex
	j                                 photoPolicyJournal
	r                                 photoPolicyRegistry
	nodes                             photoPolicyScan
	saveFail, changeFail, supportFail bool
	beforeChange                      func(*photoPolicyFake)
	writes, saves                     int
}

func newPhotoPolicyFake() *photoPolicyFake {
	return &photoPolicyFake{j: photoPolicyJournal{Schema: 1}, r: photoPolicyRegistry{Entries: map[string]photoPolicyValue{}}}
}
func policyCopy[T any](v T) T { var w T; b, _ := json.Marshal(v); _ = json.Unmarshal(b, &w); return w }
func (f *photoPolicyFake) load() (photoPolicyJournal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return policyCopy(f.j), nil
}
func (f *photoPolicyFake) save(j photoPolicyJournal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saves++
	if f.saveFail {
		return errors.New("SAVE_FAILED")
	}
	if !j.valid() {
		return errors.New("INVALID_JOURNAL")
	}
	f.j = policyCopy(j)
	return nil
}
func (f *photoPolicyFake) readRegistry() (photoPolicyRegistry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return policyCopy(f.r), nil
}
func (f *photoPolicyFake) change(expected photoPolicyRegistry, changes []photoPolicyChange) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beforeChange != nil {
		fn := f.beforeChange
		f.beforeChange = nil
		fn(f)
	}
	if f.changeFail || !f.r.same(expected) {
		return errors.New("PHOTO_POLICY_TRANSACTION_CONFLICT")
	}
	for _, c := range changes {
		switch c.Name {
		case "deny":
			f.r.Deny = c.Value
		case "retroactive":
			f.r.Retroactive = c.Value
		default:
			name := strings.TrimPrefix(c.Name, "entry:")
			if c.Value.Present {
				f.r.Entries[name] = c.Value
			} else {
				delete(f.r.Entries, name)
			}
		}
		f.writes++
	}
	return nil
}
func (f *photoPolicyFake) lock() (func(), error) { return func() {}, nil }
func (f *photoPolicyFake) supported() error {
	if f.supportFail {
		return errors.New("PHOTO_POLICY_WINDOWS_EDITION_OR_BUILD_UNSUPPORTED")
	}
	return nil
}
func (f *photoPolicyFake) scan(string) (photoPolicyScan, error) { return f.nodes, nil }
func photoPolicyTestNode(suffix string) portableNodeReceipt {
	return portableNodeReceipt{Root: `USB\VID_05AC&PID_12AB\test-ipad`, ID: `USB\VID_05AC&PID_12AB&MI_00\` + suffix, Class: portableWPDClass}
}

func TestPhotoPolicyExactIncrementalJournalAndRestore(t *testing.T) {
	f := newPhotoPolicyFake()
	f.r.Deny = photoPolicyDWORD(0)
	nodes := []portableNodeReceipt{photoPolicyTestNode("cfg3"), photoPolicyTestNode("cfg5")}
	if err := applyPhotoPolicy(f, nodes, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if len(f.j.Entries) != 2 || f.saves != 2 || len(f.r.Entries) != 2 || !f.r.Deny.same(photoPolicyDWORD(1)) {
		t.Fatal(f)
	}
	before := f.writes
	if err := applyPhotoPolicy(f, nodes, func() bool { return true }); err != nil || f.writes != before {
		t.Fatal("verified continuation rewrote policy", err)
	}
	if err := restorePhotoPolicy(f); err != nil || len(f.r.Entries) != 0 || !f.r.Deny.same(photoPolicyDWORD(0)) || f.r.Retroactive.Present || f.j.Captured {
		t.Fatal("original absence/type/data not restored", f, err)
	}
}
func TestPhotoPolicyNeverEnablesForeignDenyList(t *testing.T) {
	f := newPhotoPolicyFake()
	f.r.Entries["1"] = photoPolicyString(`USB\foreign`)
	if err := applyPhotoPolicy(f, []portableNodeReceipt{photoPolicyTestNode("cfg3")}, func() bool { return true }); err == nil || f.writes != 0 || f.saves != 0 {
		t.Fatal(err, f)
	}
}
func TestPhotoPolicyJournalFailurePreventsRegistryWrites(t *testing.T) {
	f := newPhotoPolicyFake()
	f.saveFail = true
	if err := applyPhotoPolicy(f, []portableNodeReceipt{photoPolicyTestNode("cfg3")}, func() bool { return true }); err == nil || f.writes != 0 {
		t.Fatal(err)
	}
}
func TestPhotoPolicyConcurrentExternalChangeRetainsJournalWithoutOverwrite(t *testing.T) {
	f := newPhotoPolicyFake()
	f.beforeChange = func(f *photoPolicyFake) { f.r.Entries["1"] = photoPolicyString(`USB\foreign`) }
	if err := applyPhotoPolicy(f, []portableNodeReceipt{photoPolicyTestNode("cfg3")}, func() bool { return true }); err == nil || f.writes != 0 || len(f.j.Entries) != 1 {
		t.Fatal(err, f)
	}
	if !f.r.Entries["1"].same(photoPolicyString(`USB\foreign`)) {
		t.Fatal("foreign policy overwritten")
	}
}
func TestPhotoPolicyRestoreDoesNotDisableForeignEntries(t *testing.T) {
	f := newPhotoPolicyFake()
	if err := applyPhotoPolicy(f, []portableNodeReceipt{photoPolicyTestNode("cfg3")}, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	f.r.Entries["1"] = photoPolicyString(`USB\foreign`)
	if err := restorePhotoPolicy(f); err == nil || !f.j.Captured || len(f.j.Entries) != 0 || !f.r.Deny.same(photoPolicyDWORD(1)) || len(f.r.Entries) != 1 {
		t.Fatal(err, f)
	}
	delete(f.r.Entries, "1")
	if err := restorePhotoPolicy(f); err != nil || f.j.Captured || f.r.Deny.Present {
		t.Fatal(err, f)
	}
}
func TestPhotoPolicyRestoreNeverDeletesChangedOwnedValue(t *testing.T) {
	f := newPhotoPolicyFake()
	n := photoPolicyTestNode("cfg3")
	_ = applyPhotoPolicy(f, []portableNodeReceipt{n}, func() bool { return true })
	f.r.Entries[photoPolicyName(n)] = photoPolicyString(`USB\foreign`)
	if err := restorePhotoPolicy(f); err == nil || len(f.j.Entries) != 1 || len(f.r.Entries) != 1 {
		t.Fatal(err, f)
	}
}
func TestPhotoPolicyRejectsParentsOtherInterfacesAndOtherRoots(t *testing.T) {
	for _, id := range []string{`USB\VID_05AC&PID_12AB\test-ipad`, `USB\VID_05AC&PID_12AB&MI_01\test`, `USB\VID_05AC&PID_12AB&MI_04\test`, `USB\VID_05AC&PID_12AA&MI_00\test`} {
		f := newPhotoPolicyFake()
		n := photoPolicyTestNode("cfg3")
		n.ID = id
		if err := applyPhotoPolicy(f, []portableNodeReceipt{n}, func() bool { return true }); err == nil || f.writes != 0 {
			t.Fatal(id, err)
		}
	}
	f := newPhotoPolicyFake()
	n := photoPolicyTestNode("cfg3")
	_ = applyPhotoPolicy(f, []portableNodeReceipt{n}, func() bool { return true })
	writes := f.writes
	n.ID = strings.Replace(n.ID, "cfg3", "cfg5", 1)
	n.Root = `USB\VID_05AC&PID_12AB\different`
	if err := applyPhotoPolicy(f, []portableNodeReceipt{n}, func() bool { return true }); err == nil || f.writes != writes {
		t.Fatal(err)
	}
}
func TestPhotoPolicyStartupRetainsSelectionAndReportsUnhealthyNodes(t *testing.T) {
	f := newPhotoPolicyFake()
	n := photoPolicyTestNode("cfg3")
	_ = applyPhotoPolicy(f, []portableNodeReceipt{n}, func() bool { return true })
	before := f.writes
	c := newLocalPhotoPolicyController(f)
	c.step()
	if f.writes != before || !c.blocksClassic() || c.snapshot().Phase != "waiting_master_decision" {
		t.Fatal(c.snapshot())
	}
	c.configure(func(bool) error { return nil }, func() (bool, error) { return true, nil })
	c.masterChanged(true)
	waitPolicyPreference(t, c)
	c.step()
	if f.writes != before || !c.snapshot().PolicyArmed || c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
	f.nodes = photoPolicyScan{Nodes: []portableNodeReceipt{n}, Present: 1, Unhealthy: 1, RestartRequired: true}
	_ = c.bind(n.Root)
	c.step()
	if !c.snapshot().RestartRequired || c.snapshot().Error != "PHOTO_POLICY_NATIVE_RESTART_REQUIRED" || f.writes != before {
		t.Fatal(c.snapshot())
	}
	c.masterChanged(false)
	c.step()
	if f.j.Captured || !c.snapshot().RestoreRequiresReenumeration {
		t.Fatal(c.snapshot())
	}
}
func waitPolicyPreference(t *testing.T, c *localPhotoPolicyController) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		if p := c.snapshot().Persistence; p == "saved" || p == "failed" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("policy preference did not finish", c.snapshot())
}
func TestPhotoStrategiesResolveStartupAndConflictingPreferences(t *testing.T) {
	for _, policySaved := range []bool{false, true} {
		t.Run(map[bool]string{false: "classic-resumes", true: "both-conflict"}[policySaved], func(t *testing.T) {
			f := newPhotoPolicyFake()
			policy := newLocalPhotoPolicyController(f)
			classic := newLocalPhotoController(newPhotoFake())
			classic.policyBlocked = policy.blocksClassic
			policy.classicClear = func() bool {
				return classicPhotoPolicyStateClear(classic.snapshot())
			}
			policy.classicResume = classic.resumeAfterPolicy
			classic.configure(func(bool) error { return nil }, func() (bool, error) { return true, nil })
			policy.configure(func(bool) error { return nil }, func() (bool, error) { return policySaved, nil })
			classic.masterChanged(true)
			waitPhotoPref(t, classic, "saved")
			if classic.snapshot().Requested {
				t.Fatal("classic started before policy preference was known")
			}
			policy.masterChanged(true)
			waitPolicyPreference(t, policy)
			policy.step()
			waitPhotoPref(t, classic, "saved")
			if policySaved {
				if classic.snapshot().Requested || policy.snapshot().Requested || policy.snapshot().Error != "PHOTO_POLICY_RUNTIME_ISOLATION_CONFLICT" {
					t.Fatal(classic.snapshot(), policy.snapshot())
				}
				if err := policy.set(false, strings.Repeat("a", 32)); err != nil {
					t.Fatal(err)
				}
				waitPolicyPreference(t, policy)
				policy.step()
				waitPhotoPref(t, classic, "saved")
			}
			if !classic.snapshot().Requested || policy.snapshot().Requested {
				t.Fatal("turning policy off did not release classic", classic.snapshot(), policy.snapshot())
			}
		})
	}
}

func TestPhotoStrategiesTurningClassicOffReleasesSavedPolicy(t *testing.T) {
	f := newPhotoPolicyFake()
	policy := newLocalPhotoPolicyController(f)
	classic := newLocalPhotoController(newPhotoFake())
	classic.policyBlocked = policy.blocksClassic
	policy.classicClear = func() bool { return classicPhotoPolicyStateClear(classic.snapshot()) }
	classic.configure(func(bool) error { return nil }, func() (bool, error) { return true, nil })
	policy.configure(func(bool) error { return nil }, func() (bool, error) { return true, nil })
	classic.masterChanged(true)
	waitPhotoPref(t, classic, "saved")
	policy.masterChanged(true)
	waitPolicyPreference(t, policy)
	policy.step()
	if policy.snapshot().Requested || classic.snapshot().Requested {
		t.Fatal("conflicting preferences became active")
	}
	if err := classic.set(false, strings.Repeat("b", 32)); err != nil {
		t.Fatal(err)
	}
	waitPhotoPref(t, classic, "saved")
	classic.step()
	policy.step()
	if !policy.snapshot().Requested || classic.snapshot().Requested {
		t.Fatal("classic off did not release policy", classic.snapshot(), policy.snapshot())
	}
}

func TestPhotoPolicyExitRetainsUnknownOrSelectedButRestoresKnownOff(t *testing.T) {
	for _, mode := range []string{"unknown", "selected", "off"} {
		t.Run(mode, func(t *testing.T) {
			f := newPhotoPolicyFake()
			if err := applyPhotoPolicy(f, []portableNodeReceipt{photoPolicyTestNode("cfg3")}, func() bool { return true }); err != nil {
				t.Fatal(err)
			}
			writes := f.writes
			c := newLocalPhotoPolicyController(f)
			c.configure(func(bool) error { return nil }, func() (bool, error) { return true, nil })
			if mode != "unknown" {
				c.masterChanged(mode == "selected")
				if mode == "selected" {
					waitPolicyPreference(t, c)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan struct{})
			c.run(ctx, done)
			if mode == "off" {
				if f.j.Captured || c.snapshot().RetainedOnExit {
					t.Fatal("known off retained policy", c.snapshot())
				}
			} else if f.writes != writes || !f.j.Captured || !c.snapshot().RetainedOnExit {
				t.Fatal("exit opened a policy gap", c.snapshot())
			}
		})
	}
}
