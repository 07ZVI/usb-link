package parentlifetime

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("monitor did not join")
	}
}

func TestExitJoinsInFlightWakeBeforeClosingEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exit, wakeStarted, releaseWake := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var callbackFinished atomic.Bool
	closed := make(chan struct{})
	join := watch(ctx, cancel, func() {
		close(wakeStarted)
		<-releaseWake
		callbackFinished.Store(true)
	}, func() bool { <-exit; return true }, func() {
		if !callbackFinished.Load() {
			t.Error("event closed while callback can still access it")
		}
		close(closed)
	})
	close(exit)
	await(t, wakeStarted)
	select {
	case <-closed:
		t.Fatal("closed before wake callback joined")
	default:
	}
	close(releaseWake)
	join()
	join() // callers may join after cleanup has already completed.
	await(t, closed)
}

func TestAlreadyCancelledContextUnblocksWaitAndJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wake, closed := make(chan struct{}), make(chan struct{})
	join := watch(ctx, cancel, func() { close(wake) }, func() bool { <-wake; return false }, func() { close(closed) })
	join()
	await(t, closed)
}
