package ipadncm

import (
	"testing"
	"time"
)

func TestIdleCandidateUsesOnlyOnePnPRoot(t *testing.T) {
	root := `USB\VID_05AC&PID_12AB\TEST-ROOT`
	child := `USB\VID_05AC&PID_12AB&MI_02\TEST-CHILD`
	p := idlePresenceFromIDs([]string{root, child, `USB\VID_1234&PID_5678\OTHER`}, true)
	if !p.candidate || p.absent || !p.readable {
		t.Fatal(p)
	}
	p = idlePresenceFromIDs([]string{root, root + "2"}, true)
	if p.candidate || p.absent {
		t.Fatal("ambiguous root", p)
	}
	p = idlePresenceFromIDs([]string{`USB\VID_05AC&PID_12A8\OTHER-MOBILE`}, true)
	if p.candidate || p.absent {
		t.Fatal("other device does not arm a reconnect", p)
	}
	if idlePresenceFromIDs(nil, false).absent {
		t.Fatal("error is not unplug")
	}
	if !idlePresenceFromIDs(nil, true).absent {
		t.Fatal("complete empty inventory")
	}
}
func TestTransientDisappearanceCannotRearmConnection(t *testing.T) {
	var g idleReconnectGate
	t0 := time.Unix(100, 0)
	absent := idlePresence{absent: true, readable: true}
	if g.detached(t0, absent) || g.detached(t0.Add(3*time.Second), absent) {
		t.Fatal("USB restart is not unplug")
	}
	if g.detached(t0.Add(4*time.Second), idlePresence{candidate: true, readable: true}) {
		t.Fatal("present")
	}
	if g.detached(t0.Add(5*time.Second), absent) || g.detached(t0.Add(19*time.Second), absent) {
		t.Fatal("must wait a fresh continuous absence")
	}
	if !g.detached(t0.Add(20*time.Second), absent) {
		t.Fatal("confirmed stable absence")
	}
	g.detached(t0.Add(21*time.Second), idlePresence{})
	if g.detached(t0.Add(40*time.Second), absent) {
		t.Fatal("failed query resets absence evidence")
	}
}

func TestUnifiedRetryNeedsNewAttachmentEvidence(t *testing.T) {
	t0 := time.Unix(100, 0)
	old := idlePresence{readable: true, candidate: true, identity: "ipad-a"}
	var next idleNewDeviceGate
	for _, dt := range []time.Duration{0, time.Second, 30 * time.Second} {
		if next.ready(t0.Add(dt), old.identity, old) {
			t.Fatal("same failed device must not retry-loop")
		}
	}
	fresh := idlePresence{readable: true, candidate: true, identity: "mac-b"}
	if next.ready(t0, fresh.identity, old) || next.ready(t0, old.identity, fresh) {
		t.Fatal("new candidate must settle")
	}
	if !next.ready(t0.Add(time.Second), old.identity, fresh) {
		t.Fatal("stable Mac swap should reconnect")
	}
	next.ready(t0.Add(2*time.Second), old.identity, idlePresence{})
	if next.ready(t0.Add(4*time.Second), old.identity, fresh) {
		t.Fatal("unreadable query resets stability")
	}
	g := idleReconnectGate{minimum: 3 * time.Second}
	absent := idlePresence{readable: true, absent: true}
	if g.detached(t0, absent) || g.detached(t0.Add(2*time.Second), absent) {
		t.Fatal("short reset must not rearm")
	}
	if !g.detached(t0.Add(3*time.Second), absent) {
		t.Fatal("stable disconnect must rearm even after failed attempt")
	}
}

func TestBriefReplugAndReplugDuringSuccessfulCleanup(t *testing.T) {
	now := time.Unix(100, 0)
	peer := idlePresence{readable: true, candidate: true, identity: "same-root"}
	absent := idlePresence{readable: true, absent: true}
	for _, completed := range []bool{false, true} {
		var g idleReattachGate
		if !completed {
			if g.ready(now, "same-root", peer, false) || g.ready(now.Add(4*time.Second), "same-root", peer, false) {
				t.Fatal("failed same attachment retried without unplug")
			}
			g.ready(now.Add(5*time.Second), "same-root", absent, false)
		}
		if g.ready(now.Add(6*time.Second), "same-root", peer, completed) {
			t.Fatal("unstable arrival accepted")
		}
		if !g.ready(now.Add(9*time.Second), "same-root", peer, completed) {
			t.Fatal("stable reattachment lost")
		}
	}
	var g idleReattachGate
	g.ready(now, "same-root", peer, true)
	if g.ready(now.Add(time.Second), "same-root", idlePresence{}, true) {
		t.Fatal("unknown cache accepted")
	}
	if g.ready(now.Add(3*time.Second), "same-root", peer, true) {
		t.Fatal("unknown sample did not reset stability")
	}
}

func TestConfirmedNormalReplugSkipsAdditionalDebounce(t *testing.T) {
	now := time.Unix(100, 0)
	absent := idlePresence{readable: true, absent: true}
	peer := idlePresence{readable: true, candidate: true, identity: "same-root"}
	var g idleReattachGate
	for _, elapsed := range []time.Duration{0, time.Second, 1999 * time.Millisecond, 2 * time.Second} {
		if g.ready(now.Add(elapsed), peer.identity, absent, true) {
			t.Fatal("absence must not start a connection")
		}
		if g.fastReplug != (elapsed >= 2*time.Second) {
			t.Fatal("sustained absence threshold", elapsed, g.fastReplug)
		}
	}
	arrival := now.Add(2100 * time.Millisecond)
	if !g.ready(arrival, peer.identity, peer, true) {
		t.Fatal("confirmed replug waited another two seconds")
	}
	s := rearmDiagnostic(arrival, now, peer.identity, peer, true, g, false, false, true)
	if !s.FastReplug || !s.AbsenceConfirmed || s.MinimumMS != 0 || s.Reason != "same_root_ready_after_cached_absence" {
		t.Fatal("fast-path evidence missing", s)
	}
}

func TestConfirmedAbsenceDoesNotAccelerateFailedSession(t *testing.T) {
	now := time.Unix(100, 0)
	absent := idlePresence{readable: true, absent: true}
	peer := idlePresence{readable: true, candidate: true, identity: "same-root"}
	var g idleReattachGate
	g.ready(now, peer.identity, absent, false)
	g.ready(now.Add(2*time.Second), peer.identity, absent, false)
	arrival := now.Add(3 * time.Second)
	if g.ready(arrival, peer.identity, peer, false) || g.ready(arrival.Add(1999*time.Millisecond), peer.identity, peer, false) {
		t.Fatal("failed session bypassed stability")
	}
	if !g.ready(arrival.Add(2*time.Second), peer.identity, peer, false) {
		t.Fatal("normal failed-session recovery lost")
	}
}

func TestReplugFastPathRequiresContinuousUnambiguousEvidence(t *testing.T) {
	now := time.Unix(100, 0)
	absent := idlePresence{readable: true, absent: true}
	peer := idlePresence{readable: true, candidate: true, identity: "same-root"}
	for name, interruption := range map[string]idlePresence{
		"unreadable": {},
		"ambiguous":  {readable: true},
		"other_root": {readable: true, candidate: true, identity: "other-root"},
	} {
		t.Run(name, func(t *testing.T) {
			var g idleReattachGate
			g.ready(now, peer.identity, absent, true)
			g.ready(now.Add(2*time.Second), peer.identity, absent, true)
			g.ready(now.Add(3*time.Second), peer.identity, interruption, true)
			arrival := now.Add(4 * time.Second)
			if g.ready(arrival, peer.identity, peer, true) || g.fastReplug {
				t.Fatal("uncertain transition inherited fast readiness")
			}
			if !g.ready(arrival.Add(2*time.Second), peer.identity, peer, true) {
				t.Fatal("original stable fallback lost")
			}
		})
	}
	var single idleReattachGate
	single.ready(now, peer.identity, absent, true)
	if single.ready(now.Add(3*time.Second), peer.identity, peer, true) {
		t.Fatal("one absence reading is not continuous confirmation")
	}
}
