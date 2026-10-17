package ipadncm

import (
	"context"
	"testing"
	"time"
)

func TestModeArrivalChecksImmediatelyAndUsesQueuedWakeOnlyForRecheck(t *testing.T) {
	changes := make(chan struct{}, 1)
	changes <- struct{}{} // Arrival while SET_MODE is still completing.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	checks := 0
	observeModeArrival(ctx, changes, time.Second, time.Hour, nil, func() bool {
		checks++
		return checks == 2
	})
	if checks != 2 || ctx.Err() != nil {
		t.Fatalf("queued notification did not trigger fresh proof: checks=%d err=%v", checks, ctx.Err())
	}
	checks = 0
	observeModeArrival(ctx, nil, time.Second, time.Hour, nil, func() bool { checks++; return true })
	if checks != 1 || ctx.Err() != nil {
		t.Fatal("already visible target waited for notification or polling")
	}
}

func TestModeArrivalMissingAndClosedNotificationsFallBack(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	for name, notifications := range map[string]<-chan struct{}{"registration_failed": nil, "closed": closed} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			checks := 0
			observeModeArrival(ctx, notifications, time.Second, time.Millisecond, nil, func() bool {
				checks++
				return checks == 3
			})
			if checks != 3 || ctx.Err() != nil {
				t.Fatalf("fallback failed: checks=%d err=%v", checks, ctx.Err())
			}
		})
	}
}

func TestModeArrivalCancellationNeverRunsAnotherProof(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	checks := 0
	observeModeArrival(ctx, nil, time.Hour, time.Hour, nil, func() bool {
		checks++
		cancel()
		return false
	})
	observeModeArrival(ctx, nil, time.Hour, time.Hour, nil, func() bool { checks++; return true })
	if checks != 1 {
		t.Fatalf("cancelled wait performed another device query: %d", checks)
	}
}

func TestModeArrivalUnrelatedNotificationsCannotCompleteOrExtendWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	changes := make(chan struct{}, 1)
	checks := 0
	observeModeArrival(ctx, changes, 10*time.Millisecond, time.Hour, nil, func() bool {
		checks++
		select {
		case changes <- struct{}{}:
		default:
		}
		return false // Wake hints never replace failed identity/readiness proof.
	})
	if checks < 2 || ctx.Err() != nil {
		t.Fatalf("event storm extended bounded wait: checks=%d err=%v", checks, ctx.Err())
	}
}

func TestModeArrivalDefersActiveProofUntilCachedLayoutIsReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	changes := make(chan struct{}, 1)
	cacheReads, fullReads := 0, 0
	observeModeArrival(ctx, changes, time.Second, time.Hour, func() bool {
		cacheReads++
		if cacheReads < 3 {
			changes <- struct{}{}
			return false // Old layout or absent device must not trigger descriptors.
		}
		return true
	}, func() bool {
		fullReads++
		return true
	})
	if cacheReads != 3 || fullReads != 1 || ctx.Err() != nil {
		t.Fatalf("descriptors read before layout change: cache=%d full=%d err=%v", cacheReads, fullReads, ctx.Err())
	}
}

func TestModeArrivalCacheHintCannotReplaceFailedFullProof(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := make(chan struct{}, 1)
	fullReads := 0
	observeModeArrival(ctx, changes, time.Second, time.Hour, func() bool { return true }, func() bool {
		fullReads++
		if fullReads == 2 {
			cancel()
		} else {
			changes <- struct{}{}
		}
		return false // A ready cache cannot admit a replaced or unreadable target.
	})
	if fullReads != 2 || ctx.Err() == nil {
		t.Fatalf("cache hint replaced full proof: reads=%d err=%v", fullReads, ctx.Err())
	}
}

func TestModeArrivalCancellationDuringCacheReadNeverStartsFullProof(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fullReads := 0
	observeModeArrival(ctx, nil, time.Second, time.Hour, func() bool {
		cancel()
		return true
	}, func() bool { fullReads++; return true })
	if fullReads != 0 {
		t.Fatalf("cancelled cached read started %d full checks", fullReads)
	}
}

func TestModeArrivalExpiredCacheReadNeverStartsNewFullProof(t *testing.T) {
	fullReads := 0
	observeModeArrival(context.Background(), nil, 10*time.Millisecond, time.Hour, func() bool {
		time.Sleep(20 * time.Millisecond)
		return true
	}, func() bool { fullReads++; return true })
	if fullReads != 0 {
		t.Fatalf("expired cache read started %d full checks", fullReads)
	}
}

func TestModeArrivalCacheRequiresCompleteSameTargetNewLayout(t *testing.T) {
	good := modeArrivalCacheHint{devices: 1, targetMatches: true, configuration: 5}
	if !good.permitsFullRead() {
		t.Fatal("visible new layout did not schedule fresh proof")
	}
	for name, change := range map[string]func(*modeArrivalCacheHint){
		"enumeration_failure": func(h *modeArrivalCacheHint) { h.readFailed = true },
		"partial_hub_read":    func(h *modeArrivalCacheHint) { h.hubErrors = 1 },
		"partial_port_read":   func(h *modeArrivalCacheHint) { h.portErrors = 1 },
		"absent":              func(h *modeArrivalCacheHint) { h.devices = 0 },
		"ambiguous":           func(h *modeArrivalCacheHint) { h.devices = 2 },
		"other_target":        func(h *modeArrivalCacheHint) { h.targetMatches = false },
		"old_layout":          func(h *modeArrivalCacheHint) { h.configuration = 3 },
		"unconfigured":        func(h *modeArrivalCacheHint) { h.configuration = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			hint := good
			change(&hint)
			if hint.permitsFullRead() {
				t.Fatal("uncertain cache scheduled active descriptor reads")
			}
		})
	}
}
