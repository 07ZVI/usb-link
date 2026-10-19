//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func timingCandidate(id string) idlePresence {
	return idlePresence{readable: true, candidate: true, identity: id}
}
func completeTimingDelay(context.Context, time.Duration, <-chan struct{}) string {
	return "delay_complete"
}

func TestConnectionTimingProfilesStayEnabledAcrossAttachmentsAndTime(t *testing.T) {
	for _, mode := range []string{"fast", "delayed"} {
		var c connectionTimingController
		now := time.Now()
		if err := c.set(mode, now); err != nil {
			t.Fatal(err)
		}
		for _, later := range []time.Time{now, now.Add(24 * time.Hour), now.Add(365 * 24 * time.Hour)} {
			p := c.plan(later)
			if p.mode != mode || p.fallback != time.Second || mode == "delayed" && p.delay != 12*time.Second || mode == "fast" && p.delay != 0 {
				t.Fatal(p)
			}
			_, _, ok := c.accept(context.Background(), p, "iPad", timingCandidate("private-root"), func(context.Context) (string, idlePresence) { return "iPad", timingCandidate("private-root") }, completeTimingDelay)
			if !ok {
				t.Fatal("subsequent attachment rejected")
			}
		}
		_ = c.set("normal", time.Now())
		p := c.plan(time.Now())
		if p.mode != "normal" || p.fallback != 30*time.Second || p.delay != 0 {
			t.Fatal(p)
		}
	}
}

func TestConnectionTimingDelayRejectsUnreadableChangedOrAmbiguousPresence(t *testing.T) {
	for _, fresh := range []idlePresence{{}, timingCandidate("other-private-root"), {readable: true, identity: "private-root"}, {readable: true, candidate: true}} {
		var c connectionTimingController
		_ = c.set("delayed", time.Now())
		defer c.set("normal", time.Now())
		_, _, ok := c.accept(context.Background(), c.plan(time.Now()), "iPad", timingCandidate("private-root"), func(context.Context) (string, idlePresence) { return "iPad", fresh }, completeTimingDelay)
		if ok || c.snapshot().PresenceAcceptedUTC != "" {
			t.Fatal("unproved identity accepted", fresh)
		}
	}
}

func TestConnectionTimingResetRevisionAndCancellationInterruptDelay(t *testing.T) {
	for _, reason := range []string{"normal", "fast", "cancel"} {
		t.Run(reason, func(t *testing.T) {
			var c connectionTimingController
			now := time.Now()
			_ = c.set("delayed", now)
			defer c.set("normal", time.Now())
			p := c.plan(now)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, done := make(chan struct{}), make(chan bool, 1)
			wait := func(ctx context.Context, d time.Duration, ch <-chan struct{}) string {
				close(entered)
				return waitConnectionTimingDelay(ctx, d, ch)
			}
			go func() {
				_, _, ok := c.accept(ctx, p, "iPad", timingCandidate("private"), func(context.Context) (string, idlePresence) {
					t.Error("aborted delay re-read presence")
					return "", idlePresence{}
				}, wait)
				done <- ok
			}()
			<-entered
			switch reason {
			case "cancel":
				cancel()
			default:
				_ = c.set(reason, time.Now())
			}
			select {
			case ok := <-done:
				if ok {
					t.Fatal("old revision accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("delay did not wake promptly")
			}
		})
	}
}

func TestConnectionTimingChangeDuringPresenceReadNeverAccepts(t *testing.T) {
	var c connectionTimingController
	_ = c.set("delayed", time.Now())
	_, _, ok := c.accept(context.Background(), c.plan(time.Now()), "iPad", timingCandidate("private"), func(context.Context) (string, idlePresence) {
		_ = c.set("normal", time.Now())
		return "iPad", timingCandidate("private")
	}, completeTimingDelay)
	if ok {
		t.Fatal("old identity accepted after revision change")
	}
}

func TestConnectionTimingDiagnosticsBoundedAndNoIdentity(t *testing.T) {
	var c connectionTimingController
	_ = c.set("fast", time.Now())
	defer c.set("normal", time.Now())
	c.waitBegin()
	c.wake("fallback")
	c.stage("attempt_started")
	c.stage("notification_subscribed")
	c.stage("shared_host_wait_begin")
	c.stage("shared_host_wait_end")
	_, _, ok := c.accept(context.Background(), c.plan(time.Now()), "iPad", timingCandidate("SECRET_PRIVATE_ROOT"), nil, completeTimingDelay)
	if !ok {
		t.Fatal("candidate rejected")
	}
	for i := 0; i < 10000; i++ {
		c.nativeNotice(7)
		c.wake("owner_notice")
		c.stage(strings.Repeat("untrusted", 100))
	}
	b, err := json.Marshal(c.snapshot())
	if err != nil || len(b) > 4096 || strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "untrusted") {
		t.Fatal(len(b), err, string(b))
	}
	if c.snapshot().NativeNoticeCount != 10000 {
		t.Fatal(c.snapshot())
	}
}

func TestConnectionTimingConcurrentResetReadAndArm(t *testing.T) {
	var c connectionTimingController
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = c.set("fast", time.Now())
				c.plan(time.Now())
				c.snapshot()
				_ = c.set("normal", time.Now())
			}
		}()
	}
	wg.Wait()
	_ = c.set("normal", time.Now())
	if c.snapshot().Mode != "normal" {
		t.Fatal(c.snapshot())
	}
	if err := c.set("unknown", time.Now()); err == nil {
		t.Fatal("arbitrary mode accepted")
	}
}

func TestConnectionTimingPendingControlDoesNotAccept(t *testing.T) {
	var c connectionTimingController
	_ = c.set("delayed", time.Now())
	defer c.set("normal", time.Now())
	_, _, ok := c.accept(context.Background(), c.plan(time.Now()), "iPad", timingCandidate("private"), func(context.Context) (string, idlePresence) { return "iPad", timingCandidate("private") }, completeTimingDelay, func() bool { return false })
	if ok || c.snapshot().PresenceAcceptedUTC != "" {
		t.Fatal("pending control accepted candidate")
	}
}

func TestConnectionTimingUsesTrustObserverMonotonicOrigin(t *testing.T) {
	var observer trustDiagnosticState
	if run, ms := observer.stamp(time.Now()); run != "" || ms != -1 {
		t.Fatal(run, ms)
	}
	var c connectionTimingController
	c.waitBegin()
	if c.snapshot().WaitBeginMS != -1 || c.snapshot().PresenceAcceptedMS != -1 {
		t.Fatal("uninitialized clock looked valid", c.snapshot())
	}
	started := time.Now().Add(-2 * time.Second)
	observer.start(started, "test-run")
	c.stamp = observer.stamp
	_ = c.set("delayed", time.Now())
	defer c.set("normal", time.Now())
	c.waitBegin()
	_, _, ok := c.accept(context.Background(), c.plan(time.Now()), "iPad", timingCandidate("private"), func(context.Context) (string, idlePresence) { return "iPad", timingCandidate("private") }, completeTimingDelay)
	if !ok {
		t.Fatal("candidate rejected")
	}
	c.stage("attempt_started")
	c.nativeNotice(1)
	s := c.snapshot()
	if s.RunID != "test-run" || s.WaitBeginMS < 2000 || s.DelayBeginMS < s.WaitBeginMS || s.WakeMS < s.DelayBeginMS || s.PresenceAcceptedMS < s.WakeMS || s.AttemptStartMS < s.PresenceAcceptedMS || s.NativeNoticeMS < s.AttemptStartMS {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if len(b) > 4096 {
		t.Fatal(len(b))
	}
}

func TestConnectionTimingArmClearsPreviousRoundTimes(t *testing.T) {
	var c connectionTimingController
	c.waitBegin()
	c.wake("owner_notice")
	c.stage("shared_host_wait_begin")
	c.stage("shared_host_wait_end")
	c.stage("attempt_started")
	c.stage("notification_subscribed")
	c.nativeNotice(7)
	_ = c.set("delayed", time.Now())
	defer c.set("normal", time.Now())
	s := c.snapshot()
	if s.SelectedUTC == "" || s.SelectedMS != -1 || s.WaitBeginUTC != "" || s.WaitBeginMS != -1 || s.WakeUTC != "" || s.WakeMS != -1 || s.SharedHostBeginUTC != "" || s.SharedHostBeginMS != -1 || s.SharedHostEndUTC != "" || s.SharedHostEndMS != -1 || s.AttemptStartUTC != "" || s.AttemptStartMS != -1 || s.NativeNoticeMS != -1 {
		t.Fatal(s)
	}
	if s.NativeNoticeCount != 1 || s.WakeCount != 1 || s.NativeRegistration != "subscribed" || s.CounterSemantics == "" {
		t.Fatal("process counters lost", s)
	}
	c.ownerLoop()
	if c.snapshot().WaitBeginUTC == "" {
		t.Fatal("already waiting owner did not acknowledge selection")
	}
}
