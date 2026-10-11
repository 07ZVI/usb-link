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
