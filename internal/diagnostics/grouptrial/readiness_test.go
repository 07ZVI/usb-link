package grouptrial

import (
	"context"
	"testing"
	"time"
)

func readyEvidence() ReadinessEvidence {
	return ReadinessEvidence{Devices: 1, Roots: 1, PhysicalMatches: true, RootMatches: true, RootStateReadable: true, RootProblemFree: true}
}
func TestReadinessNeverRetriesChangedOrAmbiguousTarget(t *testing.T) {
	cases := []struct {
		name string
		e    ReadinessEvidence
		want string
	}{
		{"empty", ReadinessEvidence{}, "WAITING_FOR_EXACT_ROOT"},
		{"ready", readyEvidence(), "READY"},
		{"other-port", ReadinessEvidence{Devices: 1}, "ROOT_CHANGED_BEFORE_MODE_REACTIVATION"},
		{"other-root-without-physical-enumeration", ReadinessEvidence{Roots: 1}, "ROOT_CHANGED_BEFORE_MODE_REACTIVATION"},
		{"multiple-devices", ReadinessEvidence{Devices: 2}, "REACTIVATION_TARGET_AMBIGUOUS"},
		{"multiple-roots", ReadinessEvidence{Roots: 2}, "REACTIVATION_TARGET_AMBIGUOUS"},
		{"query-error", ReadinessEvidence{QueryFailed: true}, "REACTIVATION_ENUMERATION_FAILED"},
		{"query-incomplete", ReadinessEvidence{QueryIncomplete: true}, "REACTIVATION_ENUMERATION_INCOMPLETE"},
		{"reboot", ReadinessEvidence{NeedsReboot: true}, "TARGET_WINDOWS_RESTART_REQUIRED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ReactivationReadiness(tc.e); got != tc.want {
				t.Fatalf("%s != %s", got, tc.want)
			}
		})
	}
	e := readyEvidence()
	e.RootProblemFree = false
	if ReactivationReadiness(e) != "WAITING_FOR_EXACT_ROOT" {
		t.Fatal("root still starting must wait")
	}
}
func TestWaitReactivationTransientEnumeration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	samples, err := WaitReactivation(ctx, time.Millisecond, func(context.Context) ReadinessEvidence {
		calls++
		if calls < 3 {
			return ReadinessEvidence{}
		}
		if calls == 3 {
			e := readyEvidence()
			e.RootProblemFree = false
			return e
		}
		return readyEvidence()
	})
	if err != "" || calls != 4 || len(samples) != 4 || samples[3].Status != "READY" {
		t.Fatalf("%v %s calls=%d", samples, err, calls)
	}
}
func TestWaitReactivationStopsBeforeAnotherRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	_, err := WaitReactivation(ctx, time.Millisecond, func(context.Context) ReadinessEvidence { calls++; return ReadinessEvidence{Devices: 1} })
	if err != "ROOT_CHANGED_BEFORE_MODE_REACTIVATION" || calls != 1 {
		t.Fatal(err, calls)
	}
}
func TestWaitReactivationCancelAndTimeout(t *testing.T) {
	t.Run("cancel-before-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := WaitReactivation(ctx, time.Millisecond, func(context.Context) ReadinessEvidence { t.Fatal("read after cancel"); return ReadinessEvidence{} })
		if err != "MODE_REACTIVATION_CANCELLED" {
			t.Fatal(err)
		}
	})
	t.Run("deadline-during-read", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		_, err := WaitReactivation(ctx, time.Millisecond, func(ctx context.Context) ReadinessEvidence { <-ctx.Done(); return readyEvidence() })
		if err != "EXACT_ROOT_REENUMERATION_TIMEOUT" {
			t.Fatal(err)
		}
	})
	t.Run("cancel-during-wait", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, err := WaitReactivation(ctx, time.Second, func(context.Context) ReadinessEvidence { cancel(); return ReadinessEvidence{} })
		if err != "MODE_REACTIVATION_CANCELLED" {
			t.Fatal(err)
		}
	})
}

type readinessBackend struct {
	fake
	ctx context.Context
}

func (b *readinessBackend) Activate() string {
	b.step("activate")
	_, err := WaitReactivation(b.ctx, time.Millisecond, func(context.Context) ReadinessEvidence { return ReadinessEvidence{} })
	return err
}
func TestCancelledReadinessStillRestoresOwnedTransaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &readinessBackend{ctx: ctx}
	r := Run(b, func() bool { return true })
	if r.Error != "MODE_REACTIVATION_CANCELLED" || !r.RestoreCompleted || !r.JournalCleared || r.Observation != "" {
		t.Fatalf("cancel must stop before Observe and still restore: %+v", r)
	}
	if b.calls[len(b.calls)-2] != "restore" || b.calls[len(b.calls)-1] != "clear" {
		t.Fatal(b.calls)
	}
}
