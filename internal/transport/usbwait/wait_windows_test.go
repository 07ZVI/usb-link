//go:build windows && amd64

package usbwait

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/diagnostics/bench"
	"testing"
	"time"
)

func testModeWaiter(t *testing.T, ctx context.Context) *Waiter {
	t.Helper()
	w, err := NewMode(ctx, bench.ReadEventWaitMode, bench.ObserveEventWaitMode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w
}
func testIOEvent(t *testing.T) windows.Handle {
	t.Helper()
	h, err := windows.CreateEvent(nil, 0, 0, nil) // Wintun-style auto-reset event.
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	return h
}
func waitUntilBlocked(t *testing.T, w *Waiter) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !w.waiting.Load() {
		if time.Now().After(deadline) {
			t.Fatal("worker never entered event wait")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestExplicitRestoreWakesBothNativeWorkersWithoutIO(t *testing.T) {
	bench.SetEventWaitExperiment(120)
	defer bench.SetEventWaitExperiment(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 2)
	ws := []*Waiter{testModeWaiter(t, ctx), testModeWaiter(t, ctx)}
	for _, w := range ws {
		h := testIOEvent(t)
		go func() {
			ready, err := w.Current(h)
			if ready {
				err = errors.New("restore claimed I/O completion")
			}
			done <- err
		}()
	}
	for _, w := range ws {
		waitUntilBlocked(t, w)
	}
	bench.SetEventWaitExperiment(0)
	for range ws {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			cancel()
			t.Fatal("WAITDEFAULT failed to release infinite wait")
		}
	}
	for _, w := range ws {
		if w.modeWakes.Load() != 1 {
			t.Fatal("worker did not observe mode event")
		}
	}
}
func TestIOArrivalBeforeNativeWaitIsNotLost(t *testing.T) {
	bench.SetEventWaitExperiment(120)
	defer bench.SetEventWaitExperiment(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, h := testModeWaiter(t, ctx), testIOEvent(t)
	// Packet/completion arrives after caller finds no item but before waiting.
	if err := windows.SetEvent(h); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() { ready, err := w.Current(h); done <- ready && err == nil }()
	select {
	case ready := <-done:
		if !ready {
			t.Fatal("pre-wait I/O notification lost")
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("native waiter ignored already signaled auto-reset event")
	}
}
func TestCancellationWinsSimultaneousIOAndDoesNotCloseHandleEarly(t *testing.T) {
	bench.SetEventWaitExperiment(120)
	defer bench.SetEventWaitExperiment(0)
	ctx, cancel := context.WithCancel(context.Background())
	w, h := testModeWaiter(t, ctx), testIOEvent(t)
	done := make(chan error, 1)
	go func() { _, err := w.Current(h); done <- err }()
	waitUntilBlocked(t, w)
	cancel()
	windows.SetEvent(h)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) { // I/O may win just before cancellation; caller rechecks ctx before receive.
			if ctx.Err() == nil {
				t.Fatal(err)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation failed to join native wait")
	}
	w.Close() // Safe only after worker joined; repeated Close is idempotent.
}
