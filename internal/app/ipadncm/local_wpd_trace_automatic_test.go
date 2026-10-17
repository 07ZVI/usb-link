//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAutomaticWPDTraceFollowsOnlyMasterWithoutPreferenceIO(t *testing.T) {
	c := newAutomaticLocalWPDTraceController()
	b := &wpdFake{}
	c.backend = b
	c.configure(func(bool) error { t.Fatal("automatic tracing wrote retired preference"); return nil }, func() (bool, error) {
		t.Fatal("automatic tracing read retired preference")
		return false, errors.New("old setting unavailable")
	})
	c.masterChanged(true)
	c.step()
	if s := c.snapshot(); !s.Requested || !s.Effective || s.Persistence != "automatic" || b.starts.Load() != 1 {
		t.Fatal(s)
	}
	for _, on := range []bool{false, true} {
		if err := c.set(on, strings.Repeat("a", 32)); err == nil {
			t.Fatal("retired separate switch changed automatic tracing")
		}
	}
	if !c.snapshot().Requested {
		t.Fatal("separate switch closed master tracing")
	}
	c.masterChanged(false)
	c.step()
	if s := c.snapshot(); s.Requested || s.Effective || s.Phase != "off" || b.stops.Load() != 1 {
		t.Fatal(s)
	}
}

func TestAutomaticWPDTraceOffWinsSlowStartAndRecoveryStaysVisible(t *testing.T) {
	c := newAutomaticLocalWPDTraceController()
	b := &wpdFake{begin: make(chan struct{}), release: make(chan struct{})}
	c.backend = b
	c.masterChanged(true)
	done := make(chan struct{})
	go func() { c.step(); close(done) }()
	<-b.begin
	c.masterChanged(false)
	close(b.release)
	<-done
	if c.snapshot().Effective || b.stops.Load() != 1 {
		t.Fatal("late start reopened automatic tracing", c.snapshot())
	}
	c.masterChanged(true)
	b.begin = nil
	c.step()
	b.stopErr = wpdTraceError("WPD_TRACE_STOP_FAILED", 5)
	c.masterChanged(false)
	c.step()
	if s := c.snapshot(); s.Effective || s.Phase != "recovery_pending" || s.NativeCode != 5 {
		t.Fatal("stop failure hidden", s)
	}
	b.stopErr = nil
	c.step()
	if c.snapshot().Phase != "off" {
		t.Fatal(c.snapshot())
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	cancel()
	c.masterChanged(true)
	c.step()
	if c.snapshot().Effective || b.starts.Load() != 2 {
		t.Fatal("cancelled tracing restarted", c.snapshot())
	}
}
