package launcher

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fakeProgramLoginUI() (*programLoginUI, *atomic.Bool, *atomic.Bool, *atomic.Int32) {
	dead, unknown, closed := new(atomic.Bool), new(atomic.Bool), new(atomic.Int32)
	return &programLoginUI{exited: func() (bool, bool) { return dead.Load(), !unknown.Load() }, close: func() { closed.Add(1) }}, dead, unknown, closed
}

func TestProgramLoginUISingleOwnerAndExactLifetime(t *testing.T) {
	e := newCoreProgramExit(func() {}, func() error { return nil })
	defer e.closeUILifetimes()
	a := exitOwner
	ui, dead, unknown, closed := fakeProgramLoginUI()
	if ok, err := e.registerUI(a, ui, false); err != nil || !ok {
		t.Fatal(ok, err)
	}
	b := a
	b.PID++
	b.Creation++
	second, _, _, secondClosed := fakeProgramLoginUI()
	if ok, err := e.registerUI(b, second, true); err != nil || ok || secondClosed.Load() != 1 {
		t.Fatal("second UI admitted or handle leaked")
	}
	if s := e.loginUIStatus(b); s != nil {
		t.Fatal("unregistered peer saw another UI state")
	}
	if s := e.loginUIStatus(a); s == nil || !s.ShowRequested {
		t.Fatal("duplicate did not focus original")
	}
	if e.loginUIStatus(a).ShowRequested {
		t.Fatal("focus request repeated")
	}
	unknown.Store(true)
	third, _, _, _ := fakeProgramLoginUI()
	if ok, _ := e.registerUI(b, third, false); ok {
		t.Fatal("unknown process lifetime treated as exit")
	}
	unknown.Store(false)
	dead.Store(true)
	fourth, _, _, _ := fakeProgramLoginUI()
	if ok, err := e.registerUI(b, fourth, false); err != nil || !ok || closed.Load() != 1 {
		t.Fatal("known exited instance not replaced")
	}
}

func TestRemoteRestartRequiresActualUIDrainBeforeCommit(t *testing.T) {
	e := newCoreProgramExit(func() {}, func() error { return nil })
	defer e.closeUILifetimes()
	ui, dead, unknown, _ := fakeProgramLoginUI()
	if ok, err := e.registerUI(exitOwner, ui, false); err != nil || !ok {
		t.Fatal(err)
	}
	helper := exitOwner
	helper.PID++
	helper.Creation++
	if err := e.beginWithMode(exitID1, helper, true); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	for e.snapshot().Phase != "ready" {
		select {
		case <-deadline:
			t.Fatal("not ready")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	s := e.snapshot()
	if !s.CloseFollowers || s.UIDrained {
		t.Fatal("ready is not UI exited proof", s)
	}
	repeated, _, _, repeatClosed := fakeProgramLoginUI()
	if ok, err := e.registerUI(exitOwner, repeated, false); err != nil || !ok || repeatClosed.Load() != 1 {
		t.Fatal("existing UI cannot poll shutdown")
	}
	if _, err := e.prepareCommit(exitID1, helper); err == nil {
		t.Fatal("commit while old UI alive")
	}
	newUI, _, _, closed := fakeProgramLoginUI()
	if ok, err := e.registerUI(helper, newUI, false); err == nil || ok || closed.Load() != 1 {
		t.Fatal("new UI admitted during shutdown")
	}
	unknown.Store(true)
	dead.Store(true)
	if e.snapshot().UIDrained {
		t.Fatal("unknown wait result accepted")
	}
	unknown.Store(false)
	if !e.snapshot().UIDrained {
		t.Fatal("verified exit not observed")
	}
	commit, err := e.prepareCommit(exitID1, helper)
	if err != nil {
		t.Fatal(err)
	}
	commit()
	if e.snapshot().Phase != "committed" {
		t.Fatal("commit failed")
	}
}

func TestManualExitDoesNotCloseItsOwnerBeforeCommit(t *testing.T) {
	e := newCoreProgramExit(func() {}, func() error { return nil })
	defer e.closeUILifetimes()
	ui, _, _, _ := fakeProgramLoginUI()
	_, _ = e.registerUI(exitOwner, ui, false)
	if err := e.begin(exitID1, exitOwner); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	for e.snapshot().Phase != "ready" {
		select {
		case <-deadline:
			t.Fatal("not ready")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if e.snapshot().CloseFollowers {
		t.Fatal("manual UI closed before its commit")
	}
	if _, err := e.prepareCommit(exitID1, exitOwner); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e.snapshot())
	for _, s := range []string{"SID", "Creation", "PID", "owner"} {
		if strings.Contains(string(b), s) {
			t.Fatal("private identity exposed")
		}
	}
}

func TestProgramLoginUIConcurrentLaunchHasOneOwner(t *testing.T) {
	e := newCoreProgramExit(func() {}, func() error { return nil })
	defer e.closeUILifetimes()
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := uint32(0); i < 16; i++ {
		wg.Add(1)
		go func(i uint32) {
			defer wg.Done()
			owner := exitOwner
			owner.PID += i
			owner.Creation += uint64(i)
			ui, _, _, _ := fakeProgramLoginUI()
			if ok, err := e.registerUI(owner, ui, true); err != nil {
				t.Error(err)
			} else if ok {
				admitted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatal("parallel launches admitted multiple windows")
	}
}

func TestRemoteRestartRestoreFailureKeepsUIAvailable(t *testing.T) {
	e := newCoreProgramExit(func() {}, func() error { return errors.New("failed") })
	defer e.closeUILifetimes()
	ui, _, _, _ := fakeProgramLoginUI()
	_, _ = e.registerUI(exitOwner, ui, false)
	helper := exitOwner
	helper.PID++
	helper.Creation++
	if err := e.beginWithMode(exitID1, helper, true); err != nil {
		t.Fatal(err)
	}
	waitExit(t, e, "failed")
	if s := e.snapshot(); s.CloseFollowers || s.UIDrained {
		t.Fatal("failed restoration closed old UI")
	}
	repeated, _, _, _ := fakeProgramLoginUI()
	if ok, err := e.registerUI(exitOwner, repeated, false); !ok || err != nil {
		t.Fatal("failed restore hid retry UI")
	}
	if _, err := e.prepareCommit(exitID1, helper); err == nil {
		t.Fatal("failed restore committed")
	}
}
