package wintun

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestModuleLifetimeExperimentDefaultOffAndBounded(t *testing.T) {
	if ModuleLifetimeHoldEnabled() {
		t.Fatal("experiment unexpectedly ON")
	}
	var s modulePinSet
	var pins atomic.Int32
	pin := func() error { pins.Add(1); return nil }
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.hold(1, "verified.dll", pin); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if e := s.hold(1, "same module path alias", pin); e != nil {
		t.Fatal(e)
	}
	if pins.Load() != 1 {
		t.Fatalf("per-reconnect reference leak: %d", pins.Load())
	}
	for i := uintptr(2); i <= moduleLifetimeLimit; i++ {
		if e := s.hold(i, "verified.dll", pin); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.hold(5, "verified.dll", pin); e == nil {
		t.Fatal("accepted unlimited module")
	}
	if pins.Load() != moduleLifetimeLimit {
		t.Fatal("limit still called native pin")
	}
}
func TestModuleLifetimeFailureDoesNotInventPinnedSource(t *testing.T) {
	var s modulePinSet
	calls := 0
	fail := func() error { calls++; return errors.New("native failure") }
	for _, c := range []struct {
		h    uintptr
		path string
		cb   func() error
	}{{0, "verified", fail}, {1, "", fail}, {1, "bad\x00path", fail}, {1, "verified", nil}} {
		if s.hold(c.h, c.path, c.cb) == nil {
			t.Fatal("unproven source accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid input performed native pin")
	}
	if s.hold(1, "verified", fail) == nil {
		t.Fatal("native error ignored")
	}
	if len(s.sources) != 0 {
		t.Fatal("failed pin recorded")
	}
	if e := s.hold(1, "verified", func() error { calls++; return nil }); e != nil {
		t.Fatal(e)
	}
	if calls != 2 || len(s.sources) != 1 {
		t.Fatal("known failed pin was not retryable")
	}
}
