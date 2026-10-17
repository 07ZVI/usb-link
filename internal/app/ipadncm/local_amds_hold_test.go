//go:build usblink_local_remote

package ipadncm

import (
	"context"

	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type amdsHoldFake struct {
	starts, stops, recovers       atomic.Int32
	begin, release                chan struct{}
	recoverErr, stopErr, startErr error
}

func (b *amdsHoldFake) recover() error { b.recovers.Add(1); return b.recoverErr }
func (b *amdsHoldFake) start(allowed func() bool) error {
	b.starts.Add(1)
	if b.begin != nil {
		close(b.begin)
		<-b.release
	}
	if !allowed() {
		return amdsHoldError("AMDS_HOLD_REQUEST_CANCELLED", 0)
	}
	return b.startErr
}
func (b *amdsHoldFake) stop() error { b.stops.Add(1); return b.stopErr }
func (b *amdsHoldFake) sample() (localAMDSHoldSample, error) {
	return localAMDSHoldSample{OriginalState: 4, ServiceState: 1, StartType: 2}, nil
}
func armAMDSHold(c *localAMDSHoldController, b *amdsHoldFake) {
	c.backend = b
	c.master = true
	c.state.Requested = true
	c.state.Persistence = "saved"
}
func waitAMDSHoldPref(t *testing.T, c *localAMDSHoldController, want string) {
	t.Helper()
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		if c.snapshot().Persistence == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(c.snapshot())
}
func TestLocalAMDSHoldOffCancelsSlowStartAndKeepsStatusResponsive(t *testing.T) {
	b := &amdsHoldFake{begin: make(chan struct{}), release: make(chan struct{})}
	c := newLocalAMDSHoldController()
	armAMDSHold(c, b)
	done := make(chan struct{})
	go func() { c.step(); close(done) }()
	<-b.begin
	c.masterChanged(false)
	if c.snapshot().Requested || c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
	close(b.release)
	<-done
	if b.stops.Load() != 1 || c.snapshot().Effective {
		t.Fatal("late start retained authority", c.snapshot())
	}
}
func TestLocalAMDSHoldRecoveryBeforeEnableAndRetry(t *testing.T) {
	b := &amdsHoldFake{recoverErr: amdsHoldError("AMDS_HOLD_SESSION_NOT_OWNED", 5)}
	c := newLocalAMDSHoldController()
	armAMDSHold(c, b)
	c.step()
	if b.starts.Load() != 0 || c.snapshot().Phase != "recovery_pending" || c.snapshot().NativeCode != 5 {
		t.Fatal(c.snapshot())
	}
	b.recoverErr = nil
	c.step()
	if b.starts.Load() != 1 || !c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
	c.masterChanged(false)
	b.stopErr = amdsHoldError("AMDS_HOLD_STOP_FAILED", 5)
	c.step()
	if c.snapshot().Phase != "recovery_pending" {
		t.Fatal(c.snapshot())
	}
	b.stopErr = nil
	c.step()
	if c.snapshot().Effective || c.snapshot().Phase != "off" {
		t.Fatal(c.snapshot())
	}
}
func TestLocalAMDSHoldPreferenceRaceAndRejectedAck(t *testing.T) {
	c := newLocalAMDSHoldController()
	entered, release := make(chan struct{}), make(chan struct{})
	c.configure(func(bool) error { return nil }, func() (bool, error) { close(entered); <-release; return true, nil })
	c.masterChanged(true)
	<-entered
	c.masterChanged(false)
	close(release)
	waitAMDSHoldPref(t, c, "saved")
	if c.snapshot().Requested || !c.snapshot().SavedEnabled {
		t.Fatal("stale read reopened", c.snapshot())
	}
	id := strings.Repeat("a", 32)
	if c.set(true, id) == nil || c.snapshot().RejectedID != id || c.snapshot().RejectedError == "" {
		t.Fatal(c.snapshot())
	}
	if c.set(false, id) != nil {
		t.Fatal("off rejected")
	}
	waitAMDSHoldPref(t, c, "saved")
}
func TestLocalAMDSHoldFailedSaveAndCancelledContextNeverStart(t *testing.T) {
	b := &amdsHoldFake{}
	c := newLocalAMDSHoldController()
	c.backend = b
	c.master = true
	c.configure(func(bool) error { return errors.New("private filepath") }, nil)
	if e := c.set(true, strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	waitAMDSHoldPref(t, c, "failed")
	c.step()
	if b.starts.Load() != 0 || strings.Contains(c.snapshot().Error, "private") {
		t.Fatal(c.snapshot())
	}
	c.state.Persistence = "saved"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.ctx = ctx
	c.step()
	if b.starts.Load() != 0 {
		t.Fatal("cancelled start")
	}
}
func TestLocalAMDSHoldContinuousNoExpiryAndStopJoin(t *testing.T) {
	b := &amdsHoldFake{}
	c := newLocalAMDSHoldController()
	armAMDSHold(c, b)
	c.step()
	c.step()
	if b.starts.Load() != 1 || !c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	done := make(chan struct{})
	go c.run(ctx, done)
	cancel()
	<-done
	if b.stops.Load() == 0 || c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
}

func TestLocalAMDSHoldTransitionPreservesOriginalStateAndRejectsChanges(t *testing.T) {
	for _, original := range []uint32{1, 4} {
		j := localAMDSHoldJournal{Schema: 1, Service: localAMDSHoldService, OriginalState: original, StartType: 2, ConfigHash: strings.Repeat("a", 64)}
		state := localAMDSHoldObservation{State: original, StartType: 2, ConfigHash: j.ConfigHash}
		writes := 0
		read := func() (localAMDSHoldObservation, error) { return state, nil }
		change := func(want uint32) error { writes++; state.State = want; return nil }
		if _, e := localAMDSHoldTransition(j, 1, read, change, func() bool { return true }); e != nil || state.State != 1 {
			t.Fatal(e, state)
		}
		if _, e := localAMDSHoldTransition(j, original, read, change, nil); e != nil || state.State != original {
			t.Fatal(e, state)
		}
		if original == 1 && writes != 0 {
			t.Fatal("already stopped service was unnecessarily changed")
		}
		state.StartType = 3
		before := writes
		if _, e := localAMDSHoldTransition(j, 1, read, change, nil); e == nil || writes != before {
			t.Fatal("changed configuration mutated")
		}
	}
}
func TestLocalAMDSHoldTransitionCancellationAndReadbackFailure(t *testing.T) {
	j := localAMDSHoldJournal{Schema: 1, Service: localAMDSHoldService, OriginalState: 4, StartType: 2, ConfigHash: strings.Repeat("a", 64)}
	state := localAMDSHoldObservation{State: 4, StartType: 2, ConfigHash: j.ConfigHash}
	writes := 0
	read := func() (localAMDSHoldObservation, error) { return state, nil }
	change := func(uint32) error { writes++; return nil }
	if _, e := localAMDSHoldTransition(j, 1, read, change, func() bool { return false }); e == nil || writes != 0 {
		t.Fatal("cancelled hold changed service")
	}
	if _, e := localAMDSHoldTransition(j, 1, read, change, nil); e == nil || writes != 1 {
		t.Fatal("unsuccessful transition claimed confirmed")
	}
	state.State = 2
	if _, e := localAMDSHoldTransition(j, 1, read, change, nil); e == nil || writes != 1 {
		t.Fatal("pending service transition overwritten")
	}
	if _, e := localAMDSHoldTransition(j, 7, read, change, nil); e == nil {
		t.Fatal("arbitrary SCM state allowed")
	}
}

func TestLocalAMDSHoldIdentityFailurePublishesSafeSummaryAndAllowsRetry(t *testing.T) {
	cfg := amdsIdentityTestConfig()
	cfg.Account = `DOMAIN\private-account`
	_, err := amdsHoldPortableConfigHash(cfg)
	b := &amdsHoldFake{startErr: err}
	c := newLocalAMDSHoldController()
	armAMDSHold(c, b)
	c.step()
	s := c.snapshot()
	if s.Phase != "failed" || s.Effective || s.CauseCode != "AMDS_HOLD_ACCOUNT_UNSUPPORTED" || s.Identity == nil || s.Identity.Account != "other" || !s.Identity.AbsoluteImage || !s.Identity.BasenameMatch || s.Identity.ServiceType != 0x10 {
		t.Fatal(s)
	}
	if b.stops.Load() != 1 {
		t.Fatal("failed start did not release lease")
	}
	c.step()
	if b.starts.Load() != 1 {
		t.Fatal("failure repeatedly retried without new intent")
	}
	b.startErr = nil
	c.revision++
	c.step()
	if !c.snapshot().Effective || c.snapshot().CauseCode != "" || c.snapshot().Identity != nil {
		t.Fatal("stale failed identity survived successful fresh attempt", c.snapshot())
	}
}
