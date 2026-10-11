package macconnection

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMacShadowTriggerWaitsForRealEnabledLegacySuccess(t *testing.T) {
	var trigger macFirewallShadowOnce
	ctx := context.Background()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	done := make(chan struct{})
	work := func() { close(done) }
	for _, v := range []struct {
		ctx                    context.Context
		enabled, legacy, ready bool
		work                   func()
	}{
		{nil, true, true, true, work},
		{cancelled, true, true, true, work},
		{ctx, false, true, true, work},
		{ctx, true, false, true, work},
		{ctx, true, true, false, work},
		{ctx, true, true, true, nil},
	} {
		if trigger.tryStart(v.ctx, v.enabled, v.legacy, v.ready, v.work) {
			t.Fatal("unready observation consumed successful event")
		}
	}
	if !trigger.tryStart(ctx, true, true, true, work) {
		t.Fatal("real enabled success did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("asynchronous observation not dispatched")
	}
	if trigger.tryStart(ctx, true, true, true, work) {
		t.Fatal("one connection dispatched twice")
	}
}

func TestMacShadowTriggerDoesNotJoinBlockedObservation(t *testing.T) {
	var trigger macFirewallShadowOnce
	entered, release, finished, returned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	defer func() {
		close(release)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("test observer did not release")
		}
	}()
	go func() {
		returned <- trigger.tryStart(context.Background(), true, true, true, func() {
			close(entered)
			<-release
			close(finished)
		})
	}()
	select {
	case started := <-returned:
		if !started {
			t.Fatal("success event did not dispatch")
		}
	case <-time.After(time.Second):
		t.Fatal("connection waited for blocked COM observer")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("observer did not enter")
	}
	select {
	case <-finished:
		t.Fatal("blocked observer unexpectedly finished")
	default:
	}
}

func TestMacShadowTriggerConcurrentSuccessAndIndependentAttempt(t *testing.T) {
	var trigger macFirewallShadowOnce
	var starts atomic.Int32
	var wg sync.WaitGroup
	var dispatches atomic.Int32
	done := make(chan struct{}, 2)
	work := func() { dispatches.Add(1); done <- struct{}{} }
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if trigger.tryStart(context.Background(), true, true, true, work) {
				starts.Add(1)
			}
		}()
	}
	wg.Wait()
	if starts.Load() != 1 {
		t.Fatalf("%d success jobs", starts.Load())
	}
	var next macFirewallShadowOnce
	if !next.tryStart(context.Background(), true, true, true, work) {
		t.Fatal("new attempt lost its observation")
	}
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("job missing")
		}
	}
	if dispatches.Load() != 2 {
		t.Fatalf("%d jobs", dispatches.Load())
	}
}

func TestMacShadowSourceMustBeCurrentActualCompiledLaunch(t *testing.T) {
	epoch := beginNativeFailureAttempt()
	defer beginNativeFailureAttempt()
	b := nativeChildBinding{pid: 89, creation: 101, nonce: strings.Repeat("b", 24)}
	if nativeFailureSourceBindingCurrent(epoch, b) {
		t.Fatal("unbound launch accepted")
	}
	if !bindNativeFailureChild(epoch, b) || nativeFailureSourceBindingCurrent(epoch, b) {
		t.Fatal("source-free launch treated as verified")
	}
	epoch = beginNativeFailureAttempt()
	if !bindNativeFailureChildSource(epoch, b, expectedBridgeSHA) || !nativeFailureSourceBindingCurrent(epoch, b) {
		t.Fatal("actual compiled launch rejected")
	}
	clearNativeFailure(epoch)
	if !nativeFailureSourceBindingCurrent(epoch, b) {
		t.Fatal("real Ready erased successful launch observation")
	}
	changed := b
	changed.creation++
	if nativeFailureSourceBindingCurrent(epoch, changed) {
		t.Fatal("reused PID accepted")
	}
	changed = b
	changed.nonce = strings.Repeat("c", 24)
	if nativeFailureSourceBindingCurrent(epoch, changed) {
		t.Fatal("foreign session accepted")
	}
	beginNativeFailureAttempt()
	if nativeFailureSourceBindingCurrent(epoch, b) {
		t.Fatal("old successful launch survived a new attempt")
	}
}
