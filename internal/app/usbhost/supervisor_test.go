package usbhost

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type timerRequest struct {
	delay time.Duration
	fire  chan time.Time
}

func controlledTimer() (func(time.Duration) <-chan time.Time, chan timerRequest) {
	q := make(chan timerRequest, 32)
	return func(d time.Duration) <-chan time.Time {
		c := make(chan time.Time, 1)
		q <- timerRequest{d, c}
		return c
	}, q
}
func awaitHost(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("supervisor transition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func nextTimer(t *testing.T, q <-chan timerRequest) timerRequest {
	t.Helper()
	select {
	case v := <-q:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("missing timer")
		return timerRequest{}
	}
}

func TestSupervisorRetriesPastThreeFailuresAndCapsBackoff(t *testing.T) {
	after, q := controlledTimer()
	var attempts atomic.Int32
	s := newSupervisor(context.Background(), func(context.Context) (PreparedHost, error) {
		if attempts.Add(1) <= 8 {
			return PreparedHost{}, errors.New("not ready")
		}
		return PreparedHost{Healthy: func() bool { return true }, Cleanup: func() error { return nil }}, nil
	}, after)
	defer s.Close()
	for _, want := range []time.Duration{1, 2, 4, 8, 16, 30, 30, 30} {
		v := nextTimer(t, q)
		if v.delay != want*time.Second {
			t.Fatalf("retry %v want %vs", v.delay, want)
		}
		v.fire <- time.Now()
	}
	awaitHost(t, s.Ready)
	if attempts.Load() != 9 || s.Snapshot().Failures != 8 {
		t.Fatal(s.Snapshot())
	}
	for i := 0; i < 5; i++ {
		s.Nudge()
	}
	time.Sleep(10 * time.Millisecond)
	if attempts.Load() != 9 {
		t.Fatal("ready host prepared again")
	}
}

func TestSupervisorCancelsAndDrainsGenerationBeforeCleanup(t *testing.T) {
	after, _ := controlledTimer()
	var healthy atomic.Bool
	healthy.Store(true)
	var cleaned atomic.Int32
	s := newSupervisor(context.Background(), func(context.Context) (PreparedHost, error) {
		return PreparedHost{Healthy: healthy.Load, Cleanup: func() error { cleaned.Add(1); return nil }}, nil
	}, after)
	awaitHost(t, s.Ready)
	lease, release, ok := s.Acquire(context.Background())
	if !ok {
		t.Fatal("no lease")
	}
	healthy.Store(false)
	s.Nudge()
	select {
	case <-lease.Done():
	case <-time.After(time.Second):
		t.Fatal("old lease not canceled")
	}
	if s.Ready() || cleaned.Load() != 0 {
		t.Fatal("cleanup before session joined")
	}
	healthy.Store(true)
	release()
	awaitHost(t, func() bool { return s.Snapshot().Generation == 2 && s.Ready() })
	if cleaned.Load() != 1 {
		t.Fatal("old generation cleanup missing")
	}
	s.Close()
}

func TestSupervisorRejectedAdmissionCannotReviveSameGeneration(t *testing.T) {
	after, _ := controlledTimer()
	var cleaned atomic.Int32
	s := newSupervisor(context.Background(), func(context.Context) (PreparedHost, error) {
		return PreparedHost{Healthy: func() bool { return true }, Cleanup: func() error { cleaned.Add(1); return nil }}, nil
	}, after)
	defer s.Close()
	awaitHost(t, s.Ready)
	// Inject a failed admission readback. The worker's next native readback
	// already returns true, as with a transient failure; it must still drain.
	s.mu.Lock()
	s.healthy = func() bool { return false }
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	lease, release, ok := s.Acquire(ctx)
	if !ok {
		t.Fatal("admission did not recover after rebuilding generation")
	}
	defer release()
	if lease.Err() != nil || s.Snapshot().Generation != 2 || cleaned.Load() != 1 {
		t.Fatal("rejected generation reused", s.Snapshot(), cleaned.Load())
	}
}

func TestSupervisorPartialCleanupBlocksNextPreparation(t *testing.T) {
	after, q := controlledTimer()
	var preparations, cleanups atomic.Int32
	s := newSupervisor(context.Background(), func(context.Context) (PreparedHost, error) {
		preparations.Add(1)
		return PreparedHost{Cleanup: func() error {
			if cleanups.Add(1) < 3 {
				return errors.New("retained journal")
			}
			return nil
		}}, errors.New("partial failure")
	}, after)
	defer s.Close()
	for i := 0; i < 3; i++ {
		timer := nextTimer(t, q)
		if preparations.Load() != 1 {
			t.Fatal("new prepare before durable cleanup")
		}
		timer.fire <- time.Now()
	}
	awaitHost(t, func() bool { return preparations.Load() == 2 })
}

func TestSupervisorCancellationDuringPreparationCannotPublish(t *testing.T) {
	entered := make(chan struct{})
	cleaned := make(chan struct{})
	s := NewSupervisor(context.Background(), func(ctx context.Context) (PreparedHost, error) {
		close(entered)
		<-ctx.Done()
		return PreparedHost{Healthy: func() bool { return true }, Cleanup: func() error { close(cleaned); return nil }}, nil
	})
	<-entered
	s.Close()
	if s.Ready() || s.Snapshot().Generation != 0 {
		t.Fatal("canceled preparation published")
	}
	select {
	case <-cleaned:
	default:
		t.Fatal("partial resources not cleaned")
	}
}

func TestSupervisorDeviceWakeDuringPreparationIsRetained(t *testing.T) {
	after, _ := controlledTimer()
	entered := make(chan struct{})
	finish := make(chan struct{})
	var attempts atomic.Int32
	s := newSupervisor(context.Background(), func(context.Context) (PreparedHost, error) {
		if attempts.Add(1) == 1 {
			close(entered)
			<-finish
			return PreparedHost{}, errors.New("first failure")
		}
		return PreparedHost{Healthy: func() bool { return true }, Cleanup: func() error { return nil }}, nil
	}, after)
	defer s.Close()
	<-entered
	s.Nudge()
	close(finish)
	awaitHost(t, s.Ready)
	if attempts.Load() != 2 {
		t.Fatal("device wake lost")
	}
}

func TestSupervisorFailureDiagnosticDoesNotDiscloseArbitraryMessages(t *testing.T) {
	for _, message := range []string{
		`open C:\Users\Private\file: access denied`,
		"USB_HOST_REJECTED: private-path",
		"USB_HOST_REJECTED\nPRIVATE_DATA",
		"USB_HOST_" + strings.Repeat("X", 97),
	} {
		code, native := hostFailureDiagnostic(errors.New(message))
		if code != "USB_HOST_OPERATION_FAILED" || native != 0 {
			t.Fatalf("arbitrary error disclosed: %q, %d", code, native)
		}
	}
	code, native := hostFailureDiagnostic(fmt.Errorf("private context: %w", syscall.Errno(5)))
	if code != "USB_HOST_NATIVE_OPERATION_FAILED" || native != 5 {
		t.Fatal("wrapped OS error must be numeric only", code, native)
	}
}

func TestSupervisorShowsCurrentFailureUntilSuccessfulPreparation(t *testing.T) {
	after, timers := controlledTimer()
	var attempts, cleanups atomic.Int32
	s := newSupervisor(context.Background(), func(context.Context) (PreparedHost, error) {
		if attempts.Add(1) == 1 {
			return PreparedHost{Cleanup: func() error {
				if cleanups.Add(1) == 1 {
					return syscall.Errno(5)
				}
				return nil
			}}, errors.New("USB_HOST_REMOVAL_REBOOT_UNPROVEN")
		}
		return PreparedHost{Healthy: func() bool { return true }, Cleanup: func() error { return nil }}, nil
	}, after)
	defer s.Close()
	preparation := nextTimer(t, timers)
	v := s.Snapshot()
	if v.FailurePhase != "preparation" || v.FailureCode != "USB_HOST_REMOVAL_REBOOT_UNPROVEN" || v.Ready {
		t.Fatal("preparation cause was hidden", v)
	}
	preparation.fire <- time.Now()
	cleanup := nextTimer(t, timers)
	v = s.Snapshot()
	if v.FailurePhase != "cleanup" || v.FailureCode != "USB_HOST_NATIVE_OPERATION_FAILED" || v.NativeError != 5 || attempts.Load() != 1 {
		t.Fatal("cleanup cause or ownership ordering lost", v)
	}
	cleanup.fire <- time.Now()
	awaitHost(t, s.Ready)
	v = s.Snapshot()
	if v.FailurePhase != "" || v.FailureCode != "" || v.NativeError != 0 || v.Problem != "" || v.Failures != 2 {
		t.Fatal("successful preparation retained a stale error", v)
	}
}

type supervisorCOMFailure uint32

func (e supervisorCOMFailure) Error() string         { return "private provider description" }
func (e supervisorCOMFailure) NativeHRESULT() uint32 { return uint32(e) }

func TestSupervisorRetainsTypedNativeStepAndClearsItOnReadiness(t *testing.T) {
	after, timers := controlledTimer()
	var attempts atomic.Int32
	s := newSupervisor(context.Background(), func(context.Context) (PreparedHost, error) {
		if attempts.Add(1) == 1 {
			return PreparedHost{}, fmt.Errorf("private path: %w", &netconfig.NativeStepFailure{Operation: "shared_host_firewall", Cause: supervisorCOMFailure(0x80041008)})
		}
		return PreparedHost{Healthy: func() bool { return true }, Cleanup: func() error { return nil }}, nil
	}, after)
	defer s.Close()
	timer := nextTimer(t, timers)
	v := s.Snapshot()
	if v.Ready || v.FailurePhase != "preparation" || v.FailureCode != "USB_HOST_NATIVE_STEP_FAILED" || v.NativeOperation != "shared_host_firewall" || v.NativeHRESULT != 0x80041008 || v.NativeError != 0 {
		t.Fatal(v)
	}
	timer.fire <- time.Now()
	awaitHost(t, s.Ready)
	v = s.Snapshot()
	if v.NativeOperation != "" || v.NativeHRESULT != 0 || v.FailureCode != "" {
		t.Fatal("stale native diagnostic", v)
	}
}

func TestSupervisorFirstFailureSurvivesCleanupUntilReady(t *testing.T) {
	after, timers := controlledTimer()
	var attempts, cleanups atomic.Int32
	s := newSupervisor(context.Background(), func(context.Context) (PreparedHost, error) {
		if attempts.Add(1) == 1 {
			return PreparedHost{Cleanup: func() error {
				if cleanups.Add(1) == 1 {
					return errors.New("USB_HOST_CLOSE_COMPLETION_PENDING")
				}
				return nil
			}}, &netconfig.NativeStepFailure{Operation: "shared_host_firewall", Cause: supervisorCOMFailure(0x80041008)}
		}
		return PreparedHost{Healthy: func() bool { return true }, Cleanup: func() error { return nil }}, nil
	}, after)
	defer s.Close()
	preparation := nextTimer(t, timers)
	before := s.Snapshot()
	if before.FirstFailurePhase != "preparation" || before.FirstFailureCode != "USB_HOST_NATIVE_STEP_FAILED" || before.FirstNativeOperation != "shared_host_firewall" || before.FirstNativeHRESULT != 0x80041008 || before.Ready {
		t.Fatal(before)
	}
	preparation.fire <- time.Now()
	cleanup := nextTimer(t, timers)
	current := s.Snapshot()
	if current.FailurePhase != "cleanup" || current.FailureCode != "USB_HOST_CLOSE_COMPLETION_PENDING" || current.FirstFailurePhase != before.FirstFailurePhase || current.FirstFailureCode != before.FirstFailureCode || current.FirstNativeOperation != before.FirstNativeOperation || current.FirstNativeHRESULT != before.FirstNativeHRESULT || current.Ready || attempts.Load() != 1 {
		t.Fatal("first cause overwritten or next owner admitted", current)
	}
	cleanup.fire <- time.Now()
	awaitHost(t, s.Ready)
	ready := s.Snapshot()
	if ready.FirstFailurePhase != "" || ready.FirstFailureCode != "" || ready.FirstNativeError != 0 || ready.FirstNativeOperation != "" || ready.FirstNativeHRESULT != 0 {
		t.Fatal("first cause stale after readiness", ready)
	}
	// An independent next failed cycle does not borrow the earlier native cause.
	s.fail("current_problem", "cleanup", syscall.Errno(5), 1)
	next := s.Snapshot()
	if next.FirstFailurePhase != "cleanup" || next.FirstFailureCode != "USB_HOST_NATIVE_OPERATION_FAILED" || next.FirstNativeError != 5 || next.FirstNativeOperation != "" || next.FirstNativeHRESULT != 0 || next.Ready {
		t.Fatal("next cycle borrowed old cause", next)
	}
}
func TestSupervisorFirstFailureUsesFiniteVocabulary(t *testing.T) {
	s := &Supervisor{changed: make(chan struct{})}
	s.fail("current_problem", "preparation", errors.New("USB_HOST_CUSTOM_PRIVATE_ACCOUNT"), 1)
	if s.Snapshot().FirstFailureCode != "USB_HOST_OPERATION_FAILED" {
		t.Fatal("unregistered first code retained")
	}
}
