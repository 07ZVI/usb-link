package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMonitorEvidenceIsBoundedAndSnapshotsAreIndependent(t *testing.T) {
	m := newMonitorDiagnosticCounter()
	for i := 0; i < 70; i++ {
		m.notice(7)
	}
	m.presence(idlePresence{readable: true, absent: true})
	m.presence(idlePresence{readable: true, candidate: true})
	m.presence(idlePresence{})
	r := m.snapshot()
	if r.DeviceNotices != 70 || r.DroppedNotices != 6 || len(r.NoticeSamples) != 64 || r.PresenceReads != 3 || r.AbsentSamples != 1 || r.PresentSamples != 1 || r.UnknownSamples != 1 {
		t.Fatal(r)
	}
	r.NoticeSamples[0].Class = "changed"
	if m.snapshot().NoticeSamples[0].Class != "DEVICE_NODES_CHANGED" {
		t.Fatal("snapshot aliases the retained trace")
	}
	m.notice(0xdeadbeef)
	b, _ := json.Marshal(m.snapshot())
	if strings.Contains(string(b), "deadbeef") || !strings.Contains(string(b), "OTHER_DEVICE_CHANGE") {
		t.Fatal(string(b))
	}
}
