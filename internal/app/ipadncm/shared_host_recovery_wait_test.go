package ipadncm

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func waitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for lifecycle transition")
	}
}

func TestSharedHostRecoveryJoinsRawBeforeLeaseEscapes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, rawCleaning, permitCleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
	permitLease, done := make(chan struct{}), make(chan struct{})
	var rawExited atomic.Bool
	go func() {
		defer close(done)
		lease, release, ok := acquireHostWithRecoveryAfter(ctx, func(c context.Context) (context.Context, func(), bool) {
			<-permitLease
			return c, func() {}, true
		}, func(c context.Context) {
			close(started)
			<-c.Done()
			close(rawCleaning)
			<-permitCleanup
			rawExited.Store(true)
		}, func(time.Duration) <-chan time.Time {
			ready := make(chan time.Time, 1)
			ready <- time.Now()
			return ready
		})
		if !ok || lease.Err() != nil || !rawExited.Load() {
			t.Error("normal lease escaped before raw cleanup")
		}
		if release != nil {
			release()
		}
	}()
	waitSignal(t, started)
	close(permitLease)
	waitSignal(t, rawCleaning)
	select {
	case <-done:
		t.Fatal("normal ownership escaped during raw cleanup")
	default:
	}
	close(permitCleanup)
	waitSignal(t, done)
}

func TestSharedHostRecoveryFailedRawDoesNotPublishReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rawFailed, permitLease, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, release, ok := acquireHostWithRecoveryAfter(ctx, func(c context.Context) (context.Context, func(), bool) {
			<-permitLease
			return c, func() {}, true
		}, func(context.Context) { close(rawFailed) }, func(time.Duration) <-chan time.Time {
			ch := make(chan time.Time, 1)
			ch <- time.Now()
			return ch
		})
		if !ok {
			t.Error("ordinary admission lost")
		}
		if release != nil {
			release()
		}
	}()
	waitSignal(t, rawFailed)
	select {
	case <-done:
		t.Fatal("failed raw callback became readiness")
	default:
	}
	close(permitLease)
	waitSignal(t, done)
}

func TestSharedHostRecoveryExitJoinsBothWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, acquireExited, rawCleaning, permitCleanup, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _, ok := acquireHostWithRecoveryAfter(ctx, func(c context.Context) (context.Context, func(), bool) {
			<-c.Done()
			close(acquireExited)
			return nil, nil, false
		}, func(c context.Context) {
			close(started)
			<-c.Done()
			close(rawCleaning)
			<-permitCleanup
		}, func(time.Duration) <-chan time.Time { ch := make(chan time.Time, 1); ch <- time.Now(); return ch })
		if ok {
			t.Error("canceled wait returned a lease")
		}
	}()
	waitSignal(t, started)
	cancel()
	waitSignal(t, acquireExited)
	waitSignal(t, rawCleaning)
	select {
	case <-done:
		t.Fatal("exit did not join raw cleanup")
	default:
	}
	close(permitCleanup)
	waitSignal(t, done)
}

func TestSharedHostRecoveryInvalidatedLeaseReleasedBeforeReacquire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease, invalidate := context.WithCancel(ctx)
	rawStarted, rawCleaning, permitCleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
	permitLease, done := make(chan struct{}), make(chan struct{})
	var acquisitions, releases, timers atomic.Int32
	go func() {
		defer close(done)
		got, release, ok := acquireHostWithRecoveryAfter(ctx, func(c context.Context) (context.Context, func(), bool) {
			if acquisitions.Add(1) == 1 {
				<-permitLease
				return lease, func() { releases.Add(1) }, true
			}
			if releases.Load() != 1 {
				t.Error("old lease retained while reacquiring")
			}
			return c, func() {}, true
		}, func(c context.Context) {
			close(rawStarted)
			<-c.Done()
			close(rawCleaning)
			<-permitCleanup
		}, func(time.Duration) <-chan time.Time {
			ch := make(chan time.Time, 1)
			if timers.Add(1) == 1 {
				ch <- time.Now()
			}
			return ch
		})
		if !ok || got.Err() != nil || acquisitions.Load() != 2 {
			t.Error("invalidated generation escaped", acquisitions.Load())
		}
		if release != nil {
			release()
		}
	}()
	waitSignal(t, rawStarted)
	close(permitLease)
	waitSignal(t, rawCleaning)
	invalidate()
	close(permitCleanup)
	waitSignal(t, done)
}

func TestSharedHostRecoveryAlreadyAdmittedDoesNotOpenRaw(t *testing.T) {
	never := make(chan time.Time)
	var opened atomic.Bool
	lease, release, ok := acquireHostWithRecoveryAfter(context.Background(), func(c context.Context) (context.Context, func(), bool) {
		return c, func() {}, true
	}, func(context.Context) { opened.Store(true) }, func(time.Duration) <-chan time.Time { return never })
	if !ok || lease.Err() != nil || opened.Load() {
		t.Fatal("ready host unnecessarily acquired raw USB")
	}
	release()
}
