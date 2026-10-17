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

type photoFakeBackend struct {
	journal       localPhotoJournal
	nodes         []portableNodeReceipt
	disabledNodes map[string]bool
	failSave      bool
	failRestore   bool
	writes        int
	disables      int
	restores      int
	beforeDisable func()
}

func photoNode(id string) portableNodeReceipt {
	return portableNodeReceipt{Root: `USB\VID_05AC&PID_12AB\PRIVATE-SERIAL`, ID: `USB\VID_05AC&PID_12AB&MI_00\` + id, Class: portableWPDClass}
}
func photoOriginal(n portableNodeReceipt) portablePropertyOriginal {
	return portablePropertyOriginal{Node: n}
}
func newPhotoFake() *photoFakeBackend {
	return &photoFakeBackend{journal: localPhotoJournal{Schema: 1}, disabledNodes: map[string]bool{}}
}
func (f *photoFakeBackend) load() (localPhotoJournal, error) { return f.journal, nil }
func (f *photoFakeBackend) save(j localPhotoJournal) error {
	f.writes++
	if f.failSave {
		return errors.New("write")
	}
	f.journal = j
	return nil
}
func (f *photoFakeBackend) scan(string) ([]portableNodeReceipt, error) {
	return append([]portableNodeReceipt(nil), f.nodes...), nil
}
func (f *photoFakeBackend) capture(n portableNodeReceipt) (portablePropertyOriginal, error) {
	return photoOriginal(n), nil
}
func (f *photoFakeBackend) disabled(n portableNodeReceipt) (bool, error) {
	return f.disabledNodes[n.ID], nil
}
func (f *photoFakeBackend) disable(p portablePropertyOriginal, allowed func() bool) error {
	if f.beforeDisable != nil {
		f.beforeDisable()
	}
	if !allowed() {
		return errors.New("cancelled")
	}
	found := false
	for _, v := range f.journal.Entries {
		found = found || v == p
	}
	if !found {
		return errors.New("write before journal")
	}
	f.disables++
	f.disabledNodes[p.Node.ID] = true
	return nil
}
func (f *photoFakeBackend) restore(p portablePropertyOriginal) error {
	f.restores++
	if f.failRestore {
		return errors.New("restore")
	}
	f.disabledNodes[p.Node.ID] = false
	return nil
}
func armPhoto(c *localPhotoController, root string) {
	c.mu.Lock()
	c.master = true
	c.state.Requested = true
	c.state.Persistence = "saved"
	c.root = root
	c.mu.Unlock()
}
func waitPhotoPref(t *testing.T, c *localPhotoController, want string) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		if c.snapshot().Persistence == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(c.snapshot())
}
func TestLocalPhotoJournalBeforeDisableAndInstanceReplacement(t *testing.T) {
	f := newPhotoFake()
	n := photoNode("CFG3")
	f.nodes = []portableNodeReceipt{n}
	c := newLocalPhotoController(f)
	armPhoto(c, n.Root)
	c.step()
	if f.disables != 1 || len(f.journal.Entries) != 1 || !c.snapshot().Effective {
		t.Fatal(f, c.snapshot())
	}
	next := photoNode("CFG5")
	f.nodes = []portableNodeReceipt{next}
	c.step()
	if f.disables != 2 || len(f.journal.Entries) != 2 {
		t.Fatal("new instance reused old receipt", f)
	}
	c.masterChanged(false)
	c.step()
	if len(f.journal.Entries) != 0 || f.restores != 2 || c.snapshot().Effective {
		t.Fatal(f, c.snapshot())
	}
}
func TestLocalPhotoNeverClaimsAlreadyDisabledOrEmptyScan(t *testing.T) {
	f := newPhotoFake()
	n := photoNode("NODE")
	f.nodes = []portableNodeReceipt{n}
	f.disabledNodes[n.ID] = true
	c := newLocalPhotoController(f)
	armPhoto(c, n.Root)
	c.step()
	if f.disables != 0 || len(f.journal.Entries) != 0 || !c.snapshot().Effective {
		t.Fatal(f, c.snapshot())
	}
	f.nodes = nil
	c.step()
	if c.snapshot().Effective || c.snapshot().Phase != "waiting_photo_interface" {
		t.Fatal(c.snapshot())
	}
}
func TestLocalPhotoDurableFailureAndOffEpochBlockNativeWrite(t *testing.T) {
	f := newPhotoFake()
	n := photoNode("NODE")
	f.nodes = []portableNodeReceipt{n}
	f.failSave = true
	c := newLocalPhotoController(f)
	armPhoto(c, n.Root)
	c.step()
	if f.disables != 0 || c.snapshot().Error != "PHOTO_JOURNAL_SAVE_FAILED" {
		t.Fatal(f, c.snapshot())
	}
	f.failSave = false
	f.beforeDisable = func() { c.masterChanged(false) }
	c.step()
	c.step()
	if f.disables != 0 || len(f.journal.Entries) != 0 {
		t.Fatal("late disable after off", f)
	}
}
func TestLocalPhotoStartupRestoresBeforeFreshBinding(t *testing.T) {
	f := newPhotoFake()
	n := photoNode("OLD")
	f.journal.Entries = []portablePropertyOriginal{photoOriginal(n)}
	f.disabledNodes[n.ID] = true
	f.nodes = []portableNodeReceipt{n}
	c := newLocalPhotoController(f)
	c.master = true
	c.state.Requested = true
	c.state.Persistence = "saved"
	c.step()
	if f.restores != 1 || f.disables != 0 || c.snapshot().Phase != "waiting_authorized_target" {
		t.Fatal(f, c.snapshot())
	}
	if e := c.bind(n.Root); e != nil || f.disables != 1 {
		t.Fatal(e, f)
	}
}
func TestLocalPhotoRestoreFailureRetainsObligationAndRejectsRootChange(t *testing.T) {
	f := newPhotoFake()
	n := photoNode("NODE")
	f.journal.Entries = []portablePropertyOriginal{photoOriginal(n)}
	f.failRestore = true
	c := newLocalPhotoController(f)
	if e := c.bind(n.Root); e == nil || len(f.journal.Entries) != 1 || c.snapshot().Phase != "recovery_pending" {
		t.Fatal(e, f, c.snapshot())
	}
}
func TestLocalPhotoBindingCannotCancelPreferenceRestoreOrSave(t *testing.T) {
	for _, restore := range []bool{true, false} {
		f := newPhotoFake()
		c := newLocalPhotoController(f)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		block := func() { once.Do(func() { close(entered) }); <-release }
		c.configure(func(bool) error { block(); return nil }, func() (bool, error) { block(); return true, nil })
		if restore {
			c.masterChanged(true)
		} else {
			c.master = true
			if e := c.set(true, strings.Repeat("1", 32)); e != nil {
				t.Fatal(e)
			}
		}
		<-entered
		if e := c.bind(photoNode("NODE").Root); e != nil {
			t.Fatal(e)
		}
		close(release)
		waitPhotoPref(t, c, "saved")
		if !c.snapshot().Requested || !c.snapshot().SavedEnabled {
			t.Fatal("binding lost saved selection", c.snapshot())
		}
	}
}
func TestLocalPhotoSnapshotDoesNotWaitForIOAndCancellationPreventsDisable(t *testing.T) {
	f := newPhotoFake()
	n := photoNode("NODE")
	f.nodes = []portableNodeReceipt{n}
	c := newLocalPhotoController(f)
	armPhoto(c, n.Root)
	ctx, cancel := context.WithCancel(context.Background())
	c.context = ctx
	f.beforeDisable = func() {
		if !c.snapshot().Available {
			t.Fatal("snapshot unavailable")
		}
		cancel()
	}
	c.step()
	c.step()
	if f.disables != 0 || len(f.journal.Entries) != 0 {
		t.Fatal(f, c.snapshot())
	}
}
func TestLocalPhotoSummaryBoundAndPrivacy(t *testing.T) {
	f := newPhotoFake()
	for i := 0; i < 16; i++ {
		n := photoNode(strings.Repeat("PRIVATE", 100) + string(rune('A'+i)))
		f.nodes = append(f.nodes, n)
		f.disabledNodes[n.ID] = true
	}
	c := newLocalPhotoController(f)
	armPhoto(c, photoNode("").Root)
	c.step()
	b, e := json.Marshal(c.snapshot())
	if e != nil || len(b) > 4096 || strings.Contains(string(b), "PRIVATE") || len(c.snapshot().Nodes) != 8 || c.snapshot().OmittedNodes != 8 {
		t.Fatal(string(b), e)
	}
}

func TestLocalPhotoMasterOffDuringSaveFinishesPersistenceWithoutReenable(t *testing.T) {
	f := newPhotoFake()
	c := newLocalPhotoController(f)
	entered, release := make(chan struct{}), make(chan struct{})
	c.master = true
	c.configure(func(bool) error { close(entered); <-release; return nil }, nil)
	if err := c.set(true, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	<-entered
	c.masterChanged(false)
	close(release)
	waitPhotoPref(t, c, "saved")
	c.step()
	s := c.snapshot()
	if s.Busy || s.Requested || s.Effective || !s.SavedEnabled || f.disables != 0 {
		t.Fatal(s)
	}
}

func TestLocalPhotoRejectedRequestAcknowledgementSurvivesSampling(t *testing.T) {
	c := newLocalPhotoController(newPhotoFake())
	id := strings.Repeat("a", 32)
	if c.set(true, id) == nil {
		t.Fatal("master-off accepted")
	}
	c.step()
	s := c.snapshot()
	if s.RejectedID != id || s.RejectedError != "PHOTO_DEBUG_REQUIRED" || s.Requested || s.Persistence != "unknown" {
		t.Fatal(s)
	}
}

func TestLocalPhotoNativeFailureEvidenceIsTypedBoundedAndPrivate(t *testing.T) {
	c := newLocalPhotoController(newPhotoFake())
	c.stamp = func() (string, string, int64) { return "2026-10-17T00:00:00Z", "run", 123 }
	c.publish("recovery_pending", photoFailure("PHOTO_DISABLE_FAILED", photoNativeFailure("PHOTO_NATIVE_DISABLE_FAILED", "CONFIGRET", 51, errors.New("private serial and provider response"))))
	b, e := json.Marshal(c.snapshot())
	s := c.snapshot()
	if e != nil || len(b) > 4096 || strings.Contains(string(b), "private") || s.CauseCode != "PHOTO_NATIVE_DISABLE_FAILED" || s.NativeKind != "CONFIGRET" || s.NativeCode != 51 || s.SampledMS != 123 || s.RunID != "run" {
		t.Fatal(string(b), e)
	}
}
