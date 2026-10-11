package applelease

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeService struct {
	mu            sync.Mutex
	state         uint32
	starts, stops int
	stopError     bool
	startError    bool
}

func TestWatchdogRestoresAndRevokesModeConsent(t *testing.T) {
	s := &fakeService{state: Running}
	l := New(s)
	l.watchdogAfter = 10 * time.Millisecond
	if !l.Begin(true) {
		t.Fatal("pause failed")
	}
	select {
	case <-l.done:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not finish")
	}
	r := l.Report()
	if !r.Watchdog || !r.Restored || l.Active() || s.starts != 1 {
		t.Fatalf("%+v", r)
	}
	l.Close()
}

func (s *fakeService) State() (uint32, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.state, nil }
func (s *fakeService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stops++
	s.state = Stopped
	if s.stopError {
		return errors.New("partial stop")
	}
	return nil
}
func (s *fakeService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts++
	if s.startError {
		return errors.New("cannot start")
	}
	s.state = Running
	return nil
}
func TestConsentAndOriginalStateAreRequired(t *testing.T) {
	for _, v := range []struct {
		state   uint32
		consent bool
	}{{Running, false}, {Stopped, true}} {
		s := &fakeService{state: v.state}
		l := New(s)
		if l.Begin(v.consent) {
			t.Fatal("unexpected pause")
		}
		l.Close()
		if s.starts != 0 || s.stops != 0 || s.state != v.state {
			t.Fatal("changed service without consent or original running state")
		}
	}
}
func TestPauseRestoresExactlyOnceAndDisablesModeConsent(t *testing.T) {
	s := &fakeService{state: Running}
	l := New(s)
	if !l.Begin(true) || !l.Active() {
		t.Fatal("pause failed")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l.Close() }()
	}
	wg.Wait()
	r := l.Report()
	if !r.Restored || r.After != Running || l.Active() || s.starts != 1 || s.stops != 1 {
		t.Fatalf("%+v", r)
	}
}
func TestPartialStopFailureStillRestores(t *testing.T) {
	s := &fakeService{state: Running, stopError: true}
	l := New(s)
	if l.Begin(true) {
		t.Fatal("accepted failed stop")
	}
	l.Close()
	r := l.Report()
	if !r.Restored || r.Error != "SERVICE_STOP_FAILED" || s.starts != 1 {
		t.Fatalf("%+v", r)
	}
}
func TestRestoreFailureIsReported(t *testing.T) {
	s := &fakeService{state: Running, startError: true}
	l := New(s)
	if !l.Begin(true) {
		t.Fatal("pause failed")
	}
	l.Close()
	r := l.Report()
	if r.Restored || r.RestoreError != "SERVICE_RESTART_FAILED" || l.Active() {
		t.Fatalf("%+v", r)
	}
}
