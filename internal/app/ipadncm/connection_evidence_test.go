package ipadncm

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCompactConnectionEvidenceBoundedPrivateAndStable(t *testing.T) {
	r := ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", DHCPStarted: true, DHCPACKs: 2, PeerIPv4NeighborVerified: true, HTTPVerified: true,
		Error: "PRIVATE_ERROR_PATH", DeviceAuthorization: "PRIVATE_DEVICE_ID", ProposedIPadIPv4: "PRIVATE_ADDRESS", BenchmarkURL: "PRIVATE_TOKEN"}
	m := MonitorDiagnostics{Attempts: 3, AutomaticRetries: 1, ManualRetries: 2, DroppedConnectionEvents: 4, LastAutomaticRetryReason: "PRIVATE_REASON"}
	for i := 0; i < 20; i++ {
		m.ConnectionTrace = append(m.ConnectionTrace, ConnectionEvent{Attempt: 3, Stage: "usb_mode_switch_begin", ElapsedMS: int64(i), Evidence: "PRIVATE_EVIDENCE"})
	}
	m.ConnectionTrace = append(m.ConnectionTrace, ConnectionEvent{Stage: "PRIVATE_STAGE"})
	e := compactConnectionEvidence(r, m)
	if len(e.Events) != 12 || e.RelevantEventsOmitted != 8 || e.SourceEventsOmitted != 4 || e.Events[0].ElapsedMS != 8 || !e.HasError || !e.SessionActive || e.DHCPACKs != 2 {
		t.Fatal(e)
	}
	body, err := json.Marshal(e)
	if err != nil || len(body) > 7000 || strings.Contains(string(body), "PRIVATE") {
		t.Fatalf("unbounded or private evidence: bytes=%d error=%v", len(body), err)
	}
	r.ElapsedSeconds += 5
	m.ElapsedMS += 5000
	if next := compactConnectionEvidence(r, m); !reflect.DeepEqual(e, next) {
		t.Fatal("advancing clocks changed evidence")
	}
	e.Events[0].Stage = "mutated"
	if m.ConnectionTrace[8].Stage != "usb_mode_switch_begin" {
		t.Fatal("snapshot aliases source events")
	}
}

func TestCompactConnectionEvidenceLabelsRetainedSessionAndCounts(t *testing.T) {
	r := ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_WAITING", DHCPACKs: 1, HTTPVerified: true, PeerIPv4NeighborVerified: true}
	e := compactConnectionEvidence(r, MonitorDiagnostics{Attempts: 4, AutomaticRetries: 2, ManualRetries: 1})
	if e.State != "offline" || e.SessionActive || !e.ApplicationEvidenceHistorical || e.Attempts != 4 || e.AutomaticRetries != 2 || e.ManualRetries != 1 {
		t.Fatal("retained previous-session data advertised as current", e)
	}
	if e.Events == nil || len(e.Events) != 0 {
		t.Fatal("empty evidence should remain explicit")
	}
}
