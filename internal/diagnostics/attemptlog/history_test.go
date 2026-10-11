package attemptlog

import (
	"bytes"
	"testing"
)

func TestMacAndIPadAttemptsSurviveAndSnapshotsOwnTheirBytes(t *testing.T) {
	var h History
	b := []byte(`{"device_kind":"Mac","error":"PEER_UNRESOLVED"}`)
	if h.Add(b) != nil {
		t.Fatal("valid attempt rejected")
	}
	b[0] = '!'
	h.Add([]byte(`{"device_kind":"iPad","error":"NO_MODE"}`))
	s := h.Snapshot()
	if s.Total != 2 || len(s.Attempts) != 2 || !bytes.Contains(s.Attempts[0].Result, []byte("Mac")) {
		t.Fatal("earlier device lost")
	}
	s.Attempts[0].Result[0] = '!'
	if h.Snapshot().Attempts[0].Result[0] != '{' {
		t.Fatal("snapshot changed stored history")
	}
	for i := 0; i < 8; i++ {
		h.Add([]byte(`{}`))
	}
	s = h.Snapshot()
	if s.Total != 10 || s.Omitted != 2 || s.Attempts[0].Number != 3 {
		t.Fatal("eviction lost totals")
	}
	if h.Add(bytes.Repeat([]byte("x"), MaxEntryBytes+1)) == nil || h.Add([]byte("not JSON")) == nil || h.Snapshot().Total != 10 {
		t.Fatal("invalid attempt retained")
	}
}
