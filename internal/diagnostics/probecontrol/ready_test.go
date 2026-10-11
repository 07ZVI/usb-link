package probecontrol

import "testing"

func TestReadyOnlyAfterProbeMarker(t *testing.T) {
	calls := 0
	w := NewReadyWriter(func() { calls++ })
	for _, part := range []string{"control descriptor error\n", "RESULT=STOP\n", "2026/10/01 17:00:00 READY_", "FOR_MAC"} {
		w.Write([]byte(part))
	}
	if calls != 0 {
		t.Fatal("announced readiness before completed marker line")
	}
	w.Write([]byte("\r\n"))
	if calls != 1 {
		t.Fatal("fragmented marker not delivered")
	}
	w.Write([]byte("2026/10/01 17:00:00 READY_FOR_MAC\n"))
	if calls != 1 {
		t.Fatal("duplicate notification")
	}
}

func TestErrorMentioningMarkerDoesNotAnnounceReady(t *testing.T) {
	calls := 0
	w := NewReadyWriter(func() { calls++ })
	w.Write([]byte("error: READY_FOR_MAC was never reached\n"))
	if calls != 0 {
		t.Fatal("error text triggered readiness")
	}
}
