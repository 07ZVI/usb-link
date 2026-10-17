package ipadncm

import (
	"testing"
	"time"
)

func TestTrustArchiveRetainsEventsBeforeCompactRingEviction(t *testing.T) {
	var full []TrustDiagnosticEvent
	m := trustDiagnosticState{archive: func(e TrustDiagnosticEvent) { full = append(full, e) }}
	start := time.Now()
	m.start(start, "test")
	for i := 0; i < trustEventLimit+7; i++ {
		m.event(start.Add(time.Duration(i+1)*time.Millisecond), 3, "own_operation", "usb_get_mode_begin", "")
	}
	s := m.snapshot()
	if len(s.Events) != trustEventLimit || len(full) != trustEventLimit+8 || s.Dropped != 8 {
		t.Fatal("full sink inherited the compact ring limit", len(full), s)
	}
	if full[0].Kind != "started" || full[1].Attempt != 3 || full[1].MS != 1 || full[len(full)-1].MS != int64(trustEventLimit+7) {
		t.Fatal("event ordering or original timing was lost", full)
	}
}
