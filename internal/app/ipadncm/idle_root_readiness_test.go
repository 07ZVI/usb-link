package ipadncm

import (
	"testing"
	"time"
)

func TestIdleRootReadinessReplaysEarlyEnumeration(t *testing.T) {
	p := idlePresence{readable: true, candidate: true, identity: "exact-root"}
	// Four failed captures accepted a candidate 1.5–2.6 ms after enumeration,
	// while the native root-started callback arrived another 40–52 ms later.
	for _, startedMS := range []int{40, 49, 41, 52} {
		for _, nowMS := range []int{0, startedMS - 1, startedMS} {
			o := idleRootObservation{ContextActive: true, ExactRoot: true, StateReadable: true}
			if nowMS >= startedMS {
				o.Status = 8
			}
			ready := idleRootReadiness(p.identity, p, p, o) == "root_started_not_authorization"
			if ready != (nowMS >= startedMS) {
				t.Fatalf("started=%d sample=%d ready=%v", startedMS, nowMS, ready)
			}
		}
	}
}

func TestIdleRootReadinessRejectsUnprovenTarget(t *testing.T) {
	p := idlePresence{readable: true, candidate: true, identity: "exact-root"}
	good := idleRootObservation{ContextActive: true, ExactRoot: true, StateReadable: true, Status: 8}
	for _, tc := range []struct {
		name          string
		before, after idlePresence
		o             idleRootObservation
	}{
		{"cancelled", p, p, idleRootObservation{ExactRoot: true, StateReadable: true, Status: 8}},
		{"lookup_unproven", p, p, idleRootObservation{ContextActive: true, StateReadable: true, Status: 8}},
		{"status_unreadable", p, p, idleRootObservation{ContextActive: true, ExactRoot: true, Status: 8}},
		{"restart", p, p, idleRootObservation{ContextActive: true, ExactRoot: true, StateReadable: true, Status: 0x108}},
		{"problem", p, p, idleRootObservation{ContextActive: true, ExactRoot: true, StateReadable: true, Status: 8, Problem: 22}},
		{"problem_flag", p, p, idleRootObservation{ContextActive: true, ExactRoot: true, StateReadable: true, Status: 0x408}},
		{"changed", p, idlePresence{readable: true, candidate: true, identity: "other-root"}, good},
		{"multiple", p, idlePresence{readable: true}, good},
		{"removed", p, idlePresence{readable: true, absent: true}, good},
		{"incomplete_before", idlePresence{}, p, good},
		{"incomplete_after", p, idlePresence{}, good},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if idleRootReadiness(p.identity, tc.before, tc.after, tc.o) == "root_started_not_authorization" {
				t.Fatal("unproven candidate accepted")
			}
		})
	}
}

func TestIdleRootReadinessDoesNotReplaceFailedSessionRearm(t *testing.T) {
	p := idlePresence{readable: true, candidate: true, identity: "exact-root"}
	absent := idlePresence{readable: true, absent: true}
	o := idleRootObservation{ContextActive: true, ExactRoot: true, StateReadable: true, Status: 8}
	var gate idleReattachGate
	now := time.Unix(100, 0)
	if gate.ready(now, p.identity, p, false) {
		t.Fatal("healthy root cannot rearm failed session without absence")
	}
	gate.ready(now.Add(time.Second), p.identity, absent, false)
	for _, elapsed := range []time.Duration{0, 1999 * time.Millisecond, 2 * time.Second} {
		rearmed := gate.ready(now.Add(2*time.Second+elapsed), p.identity, p, false)
		admitted := rearmed && idleRootReadiness(p.identity, p, p, o) == "root_started_not_authorization"
		if admitted != (elapsed >= 2*time.Second) {
			t.Fatalf("elapsed=%s admitted=%v", elapsed, admitted)
		}
	}
}
