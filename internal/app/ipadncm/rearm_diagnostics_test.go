package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRearmDiagnosticsPreserveTwoSecondGateAndStabilityReset(t *testing.T) {
	start := time.Unix(100, 0)
	p := idlePresence{readable: true, candidate: true, identity: "private-device-instance"}
	var gate idleReattachGate
	observe := func(at time.Duration, presence idlePresence) rearmDiagnosticSample {
		now := start.Add(at)
		ready := gate.ready(now, p.identity, presence, true)
		return rearmDiagnostic(now, start, p.identity, presence, true, gate, false, false, ready)
	}
	first := observe(0, p)
	if first.Reason != "same_root_stabilizing" || first.SameRootSinceMS != 0 || first.SameRootWaitedMS != 0 || first.MinimumMS != 2000 {
		t.Fatal(first)
	}
	second := observe(time.Second, p)
	if second.SameRootWaitedMS != 1000 || !sameRearmDiagnosticState(first, second) {
		t.Fatal("unchanged waiting state should not produce periodic archive traffic", second)
	}
	ready := observe(2*time.Second, p)
	if ready.Reason != "same_root_ready" || ready.SameRootWaitedMS != 2000 || sameRearmDiagnosticState(first, ready) {
		t.Fatal("ready boundary lost", ready)
	}
	unknown := observe(3*time.Second, idlePresence{})
	if unknown.Reason != "presence_unreadable" || unknown.SameRootSinceMS != -1 || unknown.SameRootWaitedMS != 0 {
		t.Fatal("unreadable cache must clear stability", unknown)
	}
	fresh := observe(4*time.Second, p)
	if fresh.SameRootSinceMS != 4000 || fresh.Reason != "same_root_stabilizing" || sameRearmDiagnosticState(first, fresh) {
		t.Fatal("new interval not distinguished", fresh)
	}
	encoded, err := json.Marshal(ready)
	if err != nil || strings.Contains(string(encoded), p.identity) {
		t.Fatal("private device identity entered diagnostic projection", err)
	}
}

func TestRearmDiagnosticsDistinguishRefusalAndOtherReadyPaths(t *testing.T) {
	now := time.Unix(100, 0)
	p := idlePresence{readable: true, candidate: true, identity: "private"}
	var gate idleReattachGate
	if gate.ready(now, p.identity, p, false) {
		t.Fatal("failed session admitted")
	}
	s := rearmDiagnostic(now, now, p.identity, p, false, gate, false, false, false)
	if s.Reason != "failed_session_requires_observed_absence" || s.SameRootSinceMS != -1 {
		t.Fatal(s)
	}
	for _, tc := range []struct {
		presence idlePresence
		previous string
		detached bool
		newReady bool
		reason   string
	}{
		{idlePresence{}, "private", false, false, "presence_unreadable"},
		{idlePresence{readable: true}, "private", false, false, "no_unique_candidate"},
		{idlePresence{readable: true, absent: true}, "private", false, false, "waiting_after_absence"},
		{p, "", false, false, "previous_root_unknown"},
		{p, "other", false, false, "different_root_stabilizing"},
		{p, "other", false, true, "different_root_ready"},
		{idlePresence{readable: true, absent: true}, "private", true, false, "stable_absence_ready"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			before := gate
			got := rearmDiagnostic(now, now, tc.previous, tc.presence, false, gate, tc.detached, tc.newReady, false)
			if got.Reason != tc.reason || gate != before {
				t.Fatal("projection changed gate or reason", got)
			}
		})
	}
}
