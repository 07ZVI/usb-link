package ipadncm

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type knownDev struct {
	registered, present, bad bool
	flags                    uint32
	flagsSet                 bool
}
type knownFake struct {
	journal                         localPhotoJournal
	known                           localPhotoKnown
	devs                            map[string]*knownDev
	nodes                           []portableNodeReceipt
	failKnownSave, failRestore      bool
	probes, writes, restores, scans int
	order                           []string
}

func newKnownFake() *knownFake {
	return &knownFake{journal: localPhotoJournal{Schema: 1}, known: localPhotoKnown{Schema: 1}, devs: map[string]*knownDev{}}
}
func (f *knownFake) dev(n portableNodeReceipt) *knownDev { return f.devs[strings.ToUpper(n.ID)] }
func (f *knownFake) add(n portableNodeReceipt, d knownDev) {
	f.devs[strings.ToUpper(n.ID)] = &d
	f.nodes = f.nodes[:0]
}
func (f *knownFake) remember(ns ...portableNodeReceipt) {
	for _, n := range ns {
		f.known, _ = f.known.with(knownOriginal(n))
	}
}
func (f *knownFake) load() (localPhotoJournal, error) { return f.journal, nil }
func (f *knownFake) save(j localPhotoJournal) error   { f.journal = j; return nil }
func (f *knownFake) loadKnown() (localPhotoKnown, error) {
	return f.known, nil
}
func (f *knownFake) saveKnown(k localPhotoKnown) error {
	if f.failKnownSave {
		return errors.New("write")
	}
	f.known = k
	return nil
}
func (f *knownFake) scan(string) ([]portableNodeReceipt, error) {
	f.scans++
	return append([]portableNodeReceipt(nil), f.nodes...), nil
}
func (f *knownFake) capture(n portableNodeReceipt) (portablePropertyOriginal, error) {
	return knownOriginal(n), nil
}
func (f *knownFake) disabled(n portableNodeReceipt) (bool, error) {
	d := f.dev(n)
	return d != nil && d.flags&1 != 0, nil
}
func (f *knownFake) disable(p portablePropertyOriginal, allowed func() bool) error {
	return f.disableKnown(p, allowed)
}
func (f *knownFake) restore(p portablePropertyOriginal) error {
	f.restores++
	if f.failRestore {
		return errors.New("restore")
	}
	d := f.dev(p.Node)
	d.flags, d.flagsSet = p.Value, p.Present
	f.order = append(f.order, "restore")
	return nil
}
func (f *knownFake) probe(k portablePropertyOriginal) (localPhotoProbe, error) {
	f.probes++
	d := f.dev(k.Node)
	if d == nil || !d.registered {
		return localPhotoProbe{}, nil
	}
	pr := localPhotoProbe{Registered: true, Present: d.present, Instance: !d.bad, Class: !d.bad, Root: !d.bad, Service: true, Hardware: true}
	rb := portablePropertyReadback{Readable: true, Present: d.flagsSet, Value: d.flags}
	if d.flagsSet {
		rb.Type, rb.Size = 4, 4
	}
	pr.Setup, pr.Registry = rb, rb
	if d.present && d.flags&1 != 0 {
		pr.Problem = 22
	}
	if d.flags&1 == 0 {
		o := portablePropertyOriginal{Node: k.Node, Present: d.flagsSet, Value: d.flags}
		o.Node.ConfigFlags = d.flags
		if d.flagsSet {
			o.Type, o.Size = 7, 4
		}
		pr.Original = &o
	}
	return pr, nil
}
func (f *knownFake) disableKnown(p portablePropertyOriginal, allowed func() bool) error {
	found := false
	for _, v := range f.journal.Entries {
		found = found || v == p
	}
	if !found || !allowed() {
		return errors.New("write before journal or cancelled")
	}
	d := f.dev(p.Node)
	d.flags, d.flagsSet = p.Value|1, true
	f.writes++
	return nil
}
func (f *knownFake) disabledKnown(p portablePropertyOriginal) (bool, error) {
	return f.dev(p.Node).flags == p.Value|1, nil
}

func knownCfg(id string) portableNodeReceipt { return knownNode(id) }

func onKnown(f *knownFake) *localPhotoController {
	c := newLocalPhotoController(f)
	c.runtimeDefault(true)
	return c
}

func TestKnownInstancesAreIsolatedBeforeTheDeviceIsPresent(t *testing.T) {
	f := newKnownFake()
	cfg3, cfg5 := knownCfg("CFG3"), knownCfg("CFG5")
	f.add(cfg3, knownDev{registered: true})
	f.add(cfg5, knownDev{registered: true, flags: 0x20, flagsSet: true})
	f.remember(cfg3, cfg5)
	c := onKnown(f)
	c.step()
	s := c.snapshot()
	if f.writes != 2 || len(f.journal.Entries) != 2 || s.KnownApplied != 2 || s.KnownCode != "" || s.Phase != "known_applied" || f.scans != 0 {
		t.Fatal(f, s)
	}
	if f.dev(cfg3).flags != 1 || f.dev(cfg5).flags != 0x21 {
		t.Fatal("original bits must be preserved", f.dev(cfg3), f.dev(cfg5))
	}
	c.step()
	if f.writes != 2 || f.probes != 2 {
		t.Fatal("applied instances must not be re-probed every tick", f.probes, f.writes)
	}
	// Explicit exit/off: every journaled node restored, identities remembered.
	c.runtimeDefault(false)
	c.step()
	if f.restores != 2 || len(f.journal.Entries) != 0 || len(f.known.Entries) != 2 || f.dev(cfg3).flagsSet || f.dev(cfg5).flags != 0x20 {
		t.Fatal(f, f.dev(cfg3), f.dev(cfg5))
	}
	c.runtimeDefault(true)
	c.step()
	if f.writes != 4 || len(f.journal.Entries) != 2 || c.snapshot().KnownApplied != 2 {
		t.Fatal("next start must re-apply the remembered identities", f)
	}
}

func TestKnownApplyNeverTouchesUserDisabledUnregisteredOrMismatched(t *testing.T) {
	f := newKnownFake()
	user, gone, bad, good := knownCfg("USER"), knownCfg("GONE"), knownCfg("BAD"), knownCfg("GOOD")
	f.add(user, knownDev{registered: true, flags: 1, flagsSet: true})
	f.add(gone, knownDev{})
	f.add(bad, knownDev{registered: true, bad: true})
	f.add(good, knownDev{registered: true})
	f.remember(user, gone, bad, good)
	c := onKnown(f)
	c.step()
	s := c.snapshot()
	if f.writes != 1 || len(f.journal.Entries) != 1 || f.dev(user).flags != 1 || f.dev(bad).flags != 0 || f.dev(bad).flagsSet {
		t.Fatal(f)
	}
	if s.KnownCode != "PHOTO_KNOWN_IDENTITY_MISMATCH" || s.KnownApplied != 1 || s.KnownSkipped != 2 {
		t.Fatal("mismatch must be reported with a fixed code", s)
	}
	if networkOnlyEffective(true, s) {
		t.Fatal("a rejected instance must not read as effective")
	}
}

func TestStartupKeepsOwnedEntriesWhenOnAndRestoresWhenOff(t *testing.T) {
	for _, on := range []bool{true, false} {
		f := newKnownFake()
		n := knownCfg("OLD")
		f.add(n, knownDev{registered: true, flags: 1, flagsSet: true})
		f.journal.Entries = []portablePropertyOriginal{knownOriginal(n)}
		c := newLocalPhotoController(f)
		c.runtimeDefault(on)
		c.step()
		if on && (f.restores != 0 || len(f.journal.Entries) != 1 || len(f.known.Entries) != 1) {
			t.Fatal("leftover journal must be kept and remembered", f)
		}
		if !on && (f.restores != 1 || len(f.journal.Entries) != 0) {
			t.Fatal("off must restore the leftover journal", f)
		}
	}
}

func TestReactiveFallbackLearnsNewInstancesAndSaveFailureIsNotFatal(t *testing.T) {
	f := newKnownFake()
	n := knownCfg("FIRST")
	f.add(n, knownDev{registered: true, present: true})
	f.nodes = []portableNodeReceipt{n}
	c := onKnown(f)
	c.root = n.Root
	c.step()
	if len(f.journal.Entries) != 1 || len(f.known.Entries) != 1 || !c.snapshot().Effective {
		t.Fatal(f, c.snapshot())
	}
	g := newKnownFake()
	m := knownCfg("SECOND")
	g.add(m, knownDev{registered: true, present: true})
	g.nodes = []portableNodeReceipt{m}
	g.failKnownSave = true
	d := onKnown(g)
	d.root = m.Root
	d.step()
	if len(g.journal.Entries) != 1 || !d.snapshot().Effective || d.snapshot().KnownCode != "PHOTO_KNOWN_SAVE_FAILED" {
		t.Fatal(g, d.snapshot())
	}
}

func TestApplyBeforeModeRequestOnlyReconcilesBoundRoot(t *testing.T) {
	f := newKnownFake()
	c := onKnown(f)
	c.step() // initialize with nothing remembered yet
	cfg5 := knownCfg("CFG5")
	other := knownCfg("OTHER")
	other.Root = `USB\VID_05AC&PID_12AB\OTHER-SERIAL-1`
	f.add(cfg5, knownDev{registered: true})
	f.add(other, knownDev{registered: true})
	f.remember(cfg5, other)
	c.known = f.known
	c.mu.Lock()
	c.root = cfg5.Root
	c.mu.Unlock()
	c.applyKnown()
	if f.writes != 1 || f.scans != 0 || f.dev(other).flagsSet || f.dev(cfg5).flags != 1 || len(f.journal.Entries) != 1 {
		t.Fatal(f)
	}
}

func TestPhantomRestoreFailureKeepsObligationAndNeverClaimsRestored(t *testing.T) {
	f := newKnownFake()
	n := knownCfg("CFG3")
	f.add(n, knownDev{registered: true})
	f.remember(n)
	c := onKnown(f)
	c.step()
	f.failRestore = true
	c.runtimeDefault(false)
	c.step()
	s := c.snapshot()
	if len(f.journal.Entries) != 1 || s.Phase != "recovery_pending" || s.Error != "PHOTO_RESTORE_FAILED" || !networkOnlyFromPhoto(false, s).RestorePending {
		t.Fatal(f, s)
	}
	f.failRestore = false
	c.step()
	if len(f.journal.Entries) != 0 || c.snapshot().Phase != "off" || len(f.known.Entries) != 1 {
		t.Fatal(f, c.snapshot())
	}
}

func TestUnreadableKnownStoreDisablesOnlyTheProactivePart(t *testing.T) {
	f := &knownBroken{knownFake: newKnownFake()}
	n := knownCfg("NODE")
	f.add(n, knownDev{registered: true, present: true})
	f.nodes = []portableNodeReceipt{n}
	c := onKnown(f.knownFake)
	c.backend = f
	c.root = n.Root
	c.step()
	s := c.snapshot()
	if s.KnownCode != "PHOTO_KNOWN_UNREADABLE" || !s.Effective || len(f.journal.Entries) != 1 {
		t.Fatal(f, s)
	}
}

type knownBroken struct{ *knownFake }

func (f *knownBroken) loadKnown() (localPhotoKnown, error) {
	return localPhotoKnown{}, errors.New("corrupt")
}

func TestPlanLocalPhotoKnown(t *testing.T) {
	n := knownCfg("PLAN")
	k := knownOriginal(n)
	good := func() localPhotoProbe {
		rb := portablePropertyReadback{Readable: true}
		o := knownOriginal(n)
		return localPhotoProbe{Registered: true, Instance: true, Class: true, Root: true, Service: true, Hardware: true, Setup: rb, Registry: rb, Original: &o}
	}
	disabled := func(present bool, problem uint32) localPhotoProbe {
		p := good()
		rb := portablePropertyReadback{Readable: true, Present: true, Type: 4, Size: 4, Value: 1}
		p.Setup, p.Registry, p.Present, p.Problem, p.Original = rb, rb, present, problem, nil
		return p
	}
	owned := portablePropertyOriginal{Node: n}
	for _, tc := range []struct {
		name     string
		probe    localPhotoProbe
		journal  *portablePropertyOriginal
		kind     string
		code     string
		journal_ bool
	}{
		{"fresh apply", good(), nil, knownApply, "", true},
		{"journaled apply", good(), &owned, knownApply, "", false},
		{"unregistered", localPhotoProbe{}, nil, knownSkip, "", false},
		{"user disabled", disabled(false, 0), nil, knownSkip, "", false},
		{"owned and disabled phantom", disabled(false, 0), &owned, knownVerified, "", false},
		{"owned flag but live node not disabled", disabled(true, 0), &owned, knownApply, "", false},
		{"owned and live disabled", disabled(true, 22), &owned, knownVerified, "", false},
	} {
		got := planLocalPhotoKnown(k, tc.probe, tc.journal)
		if got.Kind != tc.kind || got.Code != tc.code || got.Journal != tc.journal_ {
			t.Fatal(tc.name, got)
		}
	}
	for name, mut := range map[string]func(*localPhotoProbe){
		"instance": func(p *localPhotoProbe) { p.Instance = false },
		"class":    func(p *localPhotoProbe) { p.Class = false },
		"root":     func(p *localPhotoProbe) { p.Root = false },
		"service":  func(p *localPhotoProbe) { p.Service = false },
		"hardware": func(p *localPhotoProbe) { p.Hardware = false },
		"disagree": func(p *localPhotoProbe) {
			p.Registry.Present, p.Registry.Type, p.Registry.Size, p.Registry.Value = true, 4, 4, 2
		},
	} {
		p := good()
		mut(&p)
		if got := planLocalPhotoKnown(k, p, nil); got.Kind != knownReject || got.Code != "PHOTO_KNOWN_IDENTITY_MISMATCH" {
			t.Fatal(name, got)
		}
	}
	changed := good()
	changed.Setup = portablePropertyReadback{Readable: true, Present: true, Type: 4, Size: 4, Value: 0x20}
	changed.Registry = changed.Setup
	if got := planLocalPhotoKnown(k, changed, &owned); got.Kind != knownReject || got.Code != "PHOTO_ORIGINAL_CHANGED" {
		t.Fatal(got)
	}
	noOriginal := good()
	noOriginal.Original = nil
	if got := planLocalPhotoKnown(k, noOriginal, nil); got.Kind != knownReject || got.Code != "PHOTO_ORIGINAL_UNPROVEN" {
		t.Fatal(got)
	}
	foreign := good()
	other := knownOriginal(knownNode("OTHER"))
	foreign.Original = &other
	if got := planLocalPhotoKnown(k, foreign, nil); got.Kind != knownReject {
		t.Fatal("a capture of another instance must not be journaled", got)
	}
	wrongJournal := knownOriginal(knownNode("OTHER"))
	if got := planLocalPhotoKnown(k, good(), &wrongJournal); got.Kind != knownReject {
		t.Fatal(got)
	}
	if got := planLocalPhotoKnown(portablePropertyOriginal{}, good(), nil); got.Kind != knownReject {
		t.Fatal(got)
	}
}

func TestKnownRecordSchemaBoundsAndHardwareIDs(t *testing.T) {
	k := localPhotoKnown{Schema: 1}
	for i := 0; i < 20; i++ {
		k, _ = k.with(knownOriginal(knownNode(strings.Repeat("A", 1) + string(rune('A'+i)))))
	}
	if len(k.Entries) != 16 || !strings.HasSuffix(k.Entries[0].Node.ID, "E") || !k.valid() {
		t.Fatal("oldest identity must be dropped at the bound", len(k.Entries))
	}
	same, changed := k.with(k.Entries[3])
	if changed || len(same.Entries) != 16 {
		t.Fatal("identical record must not rewrite")
	}
	n := k.Entries[3]
	n.Present, n.Type, n.Size, n.Value, n.Node.ConfigFlags = true, 7, 4, 0x20, 0x20
	if next, changed := k.with(n); !changed || len(next.Entries) != 16 || next.Entries[3] != n {
		t.Fatal("a fresh capture replaces the record in place")
	}
	bad := knownOriginal(knownNode("X"))
	bad.Node.OriginalDisabled = true
	if _, changed := k.with(bad); changed {
		t.Fatal("originally disabled node must never be remembered")
	}
	b, _ := json.Marshal(k)
	if got, err := decodeLocalPhotoKnown(b); err != nil || len(got.Entries) != 16 {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"schema":2,"entries":[]}`, `{"schema":1,"entries":[],"x":1}`, `{"schema":1,"entries":[]}{}`, strings.Repeat(" ", localPhotoKnownLimit+1)} {
		if _, err := decodeLocalPhotoKnown([]byte(body)); err == nil {
			t.Fatal("invalid record accepted", body)
		}
	}
	for _, ids := range [][]string{{`USB\VID_05AC&PID_12AB&REV_1316&MI_00`, `usb\vid_05ac&pid_12ab&mi_00`}, {`USB\VID_05AC&PID_12AB&MI_00`}} {
		if !localPhotoHardwareMatch(ids) {
			t.Fatal(ids)
		}
	}
	for _, ids := range [][]string{nil, {`USB\VID_05AC&PID_12AB&MI_01`}, {`USB\VID_05AC&PID_12AB`}, {`USB\VID_05AC&PID_12A8&MI_00`}, {`USB\VID_05AC&PID_12AB&MI_00X`}} {
		if localPhotoHardwareMatch(ids) {
			t.Fatal(ids)
		}
	}
}

func TestPhantomOriginalCaptureRequiresAgreeingEnabledProperty(t *testing.T) {
	n := knownCfg("PH")
	rb := func(present bool, v uint32) portablePropertyReadback {
		r := portablePropertyReadback{Readable: true, Present: present, Value: v}
		if present {
			r.Type, r.Size = 4, 4
		}
		return r
	}
	n.ConfigFlags = 0x20
	if p, err := localPhotoPhantomOriginal(n, rb(true, 0x20), rb(true, 0x20)); err != nil || !p.Present || p.Type != 7 || !p.valid() {
		t.Fatal(p, err)
	}
	n.ConfigFlags = 0
	if p, err := localPhotoPhantomOriginal(n, rb(false, 0), rb(false, 0)); err != nil || p.Present || !p.valid() {
		t.Fatal(p, err)
	}
	if _, err := localPhotoPhantomOriginal(n, rb(true, 0), rb(false, 0)); err == nil {
		t.Fatal("disagreeing reads accepted")
	}
	if _, err := localPhotoPhantomOriginal(n, rb(true, 4), rb(true, 4)); err == nil {
		t.Fatal("value differing from the receipt accepted")
	}
	n.ConfigFlags, n.OriginalDisabled = 1, true
	if _, err := localPhotoPhantomOriginal(n, rb(true, 1), rb(true, 1)); err == nil {
		t.Fatal("already disabled phantom must never be captured as an original")
	}
}

func TestDisableReadyAcceptsPersistedBitOnlyForOwnedStartedNode(t *testing.T) {
	p := knownOriginal(knownNode("DR"))
	obs := PortableNodeObservation{InstanceMatches: true, ClassMatches: true, RootMatches: true, StateReadable: true, FlagsReadable: true, Status: 8, FlagsAbsent: true}
	if !localPhotoDisableReady(obs, p) {
		t.Fatal("pristine original must be disableable")
	}
	obs.ConfigFlags, obs.FlagsAbsent = 1, false
	if !localPhotoDisableReady(obs, p) {
		t.Fatal("persisted bit without live disable must be completed")
	}
	obs.Problem = 22
	if localPhotoDisableReady(obs, p) {
		t.Fatal("already disabled node needs no second disable")
	}
	obs.Problem, obs.ConfigFlags = 0, 0x20
	if localPhotoDisableReady(obs, p) {
		t.Fatal("foreign flag bits must stop the write")
	}
	obs.ConfigFlags, obs.RootMatches = 1, false
	if localPhotoDisableReady(obs, p) {
		t.Fatal("identity loss must stop the write")
	}
}

func TestNetworkOnlyStatusReflectsReadbacksNotTheSwitch(t *testing.T) {
	applied := localPhotoStatus{Requested: true, KnownApplied: 2, KnownNodes: 2, OwnedNodes: 2, Phase: "known_applied"}
	if s := networkOnlyFromPhoto(true, applied); !s.Effective || s.Error != "" || s.RestorePending {
		t.Fatal(s)
	}
	if networkOnlyFromPhoto(false, applied).Effective {
		t.Fatal("switch off cannot be effective")
	}
	if s := networkOnlyFromPhoto(false, localPhotoStatus{Phase: "recovering", OwnedNodes: 2}); !s.Restoring || s.Effective {
		t.Fatal(s)
	}
	if s := networkOnlyFromPhoto(false, localPhotoStatus{Phase: "off"}); s.Restoring || s.RestorePending || s.Error != "" {
		t.Fatal(s)
	}
	pending := localPhotoStatus{Phase: "recovery_pending", Error: "PHOTO_RESTORE_FAILED", OwnedNodes: 1}
	if s := networkOnlyFromPhoto(false, pending); !s.RestorePending || s.Error != "PHOTO_RESTORE_FAILED" || s.Restoring {
		t.Fatal(s)
	}
	present := localPhotoStatus{Requested: true, ObservedNodes: 1, Effective: false, KnownApplied: 2}
	if networkOnlyFromPhoto(true, present).Effective {
		t.Fatal("known instances cannot mask an unisolated present node")
	}
	failed := localPhotoStatus{Requested: true, KnownApplied: 1, KnownCode: "PHOTO_KNOWN_IDENTITY_MISMATCH"}
	if s := networkOnlyFromPhoto(true, failed); s.Effective || s.Error != "PHOTO_KNOWN_IDENTITY_MISMATCH" {
		t.Fatal(s)
	}
}

func knownNode(id string) portableNodeReceipt {
	return portableNodeReceipt{Root: `USB\VID_05AC&PID_12AB\PRIVATE-SERIAL`, ID: `USB\VID_05AC&PID_12AB&MI_00\` + id, Class: portableWPDClass}
}
func knownOriginal(n portableNodeReceipt) portablePropertyOriginal {
	return portablePropertyOriginal{Node: n}
}
