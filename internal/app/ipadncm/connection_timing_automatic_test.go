//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"testing"
	"time"
)

func TestAutomaticDetectionNeedsNoPreferenceAndKeepsCandidateChecks(t *testing.T) {
	c := newAutomaticConnectionTimingController(nil)
	p := c.plan(time.Now())
	if p.mode != "fast" || p.fallback != time.Second || p.delay != 0 || c.snapshot().Persistence != "automatic" {
		t.Fatal(p, c.snapshot())
	}
	for _, presence := range []idlePresence{{}, {readable: true, candidate: true}, {readable: true, identity: "private"}} {
		if _, _, ok := c.accept(context.Background(), p, "iPad", presence, nil, nil); ok {
			t.Fatal("automatic detection accepted an unproved candidate")
		}
	}
	if _, _, ok := c.accept(context.Background(), p, "iPad", timingCandidate("private"), nil, nil, func() bool { return false }); ok {
		t.Fatal("automatic detection bypassed pending control")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, ok := c.accept(ctx, p, "iPad", timingCandidate("private"), nil, nil); ok {
		t.Fatal("automatic detection ignored cancellation")
	}
}

func TestAutomaticDetectionRetiresStoredDelayAndCannotRestoreIt(t *testing.T) {
	var c connectionTimingController
	c.configurePersistence(func(string) error { t.Fatal("automatic detection wrote an obsolete preference"); return nil }, func() (string, error) {
		t.Fatal("automatic detection read an obsolete preference")
		return "delayed", nil
	})
	_ = c.set("delayed", time.Now())
	previous := c.plan(time.Now())
	c.useAutomaticDetection()
	select {
	case <-previous.changed:
	default:
		t.Fatal("old delayed wait was not cancelled")
	}
	if err := c.restoreSelection(func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		c.useAutomaticDetection()
		if p := c.plan(time.Now()); p.mode != "fast" || p.delay != 0 || p.fallback != time.Second {
			t.Fatal(p)
		}
	}
}
