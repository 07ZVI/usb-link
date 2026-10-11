package ipadncm

import "testing"

func TestNetDebugBoundsAndTransitions(t *testing.T) {
	l := &netDebugLog{}
	for i := 0; i < netDebugMaxEvents+30; i++ {
		l.event("x", "")
	}
	if got := len(l.export().Events); got != netDebugMaxEvents {
		t.Fatalf("events=%d", got)
	}
	if !l.peer("reachable") || l.peer("reachable") || !l.peer("unreachable") {
		t.Fatal("peer transitions")
	}
	for i := 0; i < netDebugMaxSnapshots+3; i++ {
		l.store(NetDebugSnapshot{Reason: "r"}, true)
	}
	l.store(NetDebugSnapshot{Reason: "periodic"}, false)
	e := l.export()
	if len(e.Captured) != netDebugMaxSnapshots || e.Latest == nil || e.Latest.Reason != "periodic" || e.PeerState != "unreachable" {
		t.Fatalf("export %+v", e)
	}
}
