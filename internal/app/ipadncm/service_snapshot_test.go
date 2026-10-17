package ipadncm

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
	"testing"
)

func TestDesktopSnapshotHistoryCannotGrowPastTransportBudget(t *testing.T) {
	r := ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", WindowsIPv4: "10.6.9.1", ProposedIPadIPv4: "10.6.9.3", DHCPStarted: true, DHCPACKs: 1, PeerIPv4NeighborVerified: true}
	for i := 0; i < 900; i++ {
		r.Performance.Record(ipadsession.PerformanceSample{RecordedUTC: "2026-10-16T12:00:00.123456789Z", ElapsedMS: int64(i * 1000), IntervalMS: 1000, QueryMS: 3, TransmitMbps: 300, ReceiveMbps: 20, FaultDeltaValid: true, Faults: ipadsession.InterfaceFaults{OutDiscards: 1}})
	}
	source := ServiceDisplaySnapshot{Desktop: map[string]any{"event": "status", "version": "0.10.19", "detail": strings.Repeat("诊断\n", 2000)}, Connections: map[string]ApplicationResult{"iPad": r, "Mac": {DeviceKind: "Mac", Status: "MAC_RUNNING"}}}
	original, _ := json.Marshal(source)
	if len(original) <= 48<<10 {
		t.Fatal("fixture does not reproduce oversize", len(original))
	}
	b, err := encodeServiceDisplaySnapshot(source)
	if err != nil || len(b) > 48<<10 {
		t.Fatal("snapshot still exceeds budget", len(b), err)
	}
	var decoded ServiceDisplaySnapshot
	if err = json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	got := decoded.Connections["iPad"]
	if !reflect.DeepEqual(desktopDeviceStatus(r, false), desktopDeviceStatus(got, false)) {
		t.Fatal("desktop projection changed")
	}
	if got.Performance.Samples != 900 || got.Performance.HistoryOmitted != 900 || got.Performance.Faults != r.Performance.Faults || len(got.Performance.History) != 0 || len(got.Performance.FaultEvents) != 0 {
		t.Fatal("aggregate/history contract lost")
	}
	if len(source.Connections["iPad"].Performance.History) != 600 || len(source.Connections["iPad"].Performance.FaultEvents) != 64 {
		t.Fatal("core history mutated")
	}
	t.Logf("original=%d projected=%d", len(original), len(b))
}

func TestDesktopSnapshotUnexpectedOversizeRemainsExplicit(t *testing.T) {
	_, err := encodeServiceDisplaySnapshot(ServiceDisplaySnapshot{Desktop: strings.Repeat("x", 60<<10)})
	if err == nil || desktopReadErrorCode(err) != "CORE_DESKTOP_STATUS_TOO_LARGE" {
		t.Fatal(err)
	}
	if desktopReadErrorCode(fmt.Errorf("private path")) != "CORE_UI_READ_FAILED" {
		t.Fatal("raw error exposed")
	}
}

func TestDesktopExperimentControlKeepsRecoveryAuthorityWithoutDuplicatingEvents(t *testing.T) {
	value := map[string]any{"available": true, "saved_enabled": true, "requested": false, "effective": false, "phase": "recovery_pending", "request_id": strings.Repeat("a", 32), "recovery_required": true, "error": "DIRECT_REPLUG_REQUIRED", "observed_configurations": strings.Repeat("x", 8192), "recent": strings.Repeat("x", 8192)}
	b, err := json.Marshal(desktopExperimentControl(value))
	var got map[string]any
	if err != nil || json.Unmarshal(b, &got) != nil || len(b) > 512 || got["request_id"] != value["request_id"] || got["recovery_required"] != true || got["saved_enabled"] != true || got["effective"] != false || got["phase"] != "recovery_pending" || got["error"] != value["error"] {
		t.Fatal(string(b), err)
	}
	if _, ok := got["recent"]; ok {
		t.Fatal("event array duplicated in control envelope")
	}
	if desktopExperimentControl(nil) != nil {
		t.Fatal("public nil state must remain absent")
	}
}

func TestDesktopUSBTraceSummaryPreservesCoverageAndLossWithoutEventData(t *testing.T) {
	source := map[string]any{"available": true, "active": true, "phase": "metadata_only", "coverage": "incomplete", "target_scope": "unknown", "received": 21, "accepted": 1, "events_lost": 20, "queue_overflow": 3, "schema_rejected": 4, "realtime_buffers_lost": 5, "started_utc": "2026-10-17T10:00:00Z", "last_event_utc": "2026-10-17T10:01:00Z", "recent": strings.Repeat("x", 8192), "providers": strings.Repeat("x", 8192)}
	b, err := json.Marshal(desktopUSBTraceSummary(source))
	var got map[string]any
	if err != nil || json.Unmarshal(b, &got) != nil {
		t.Fatal(err)
	}
	if len(b) > 1024 || got["coverage"] != "incomplete" || got["target_scope"] != "unknown" || got["events_lost"] != float64(20) || got["accepted"] != float64(1) || got["started_utc"] != source["started_utc"] || got["recent"] != nil || got["providers"] != nil {
		t.Fatal(string(b))
	}
	if desktopUSBTraceSummary(nil) != nil || desktopUSBTraceSummary(map[string]any{"available": false, "phase": "local_build_required"}) != nil {
		t.Fatal("public/old state must remain absent")
	}
	recovery := desktopUSBTraceSummary(map[string]any{"available": false, "phase": "recovery_pending", "error": "USB_TRACE_STOP_FAILED"})
	if recovery == nil {
		t.Fatal("public recovery failure must not be hidden")
	}
}

func TestDesktopPnPTraceSummaryKeepsNativeNotificationLoss(t *testing.T) {
	b, err := json.Marshal(desktopUSBTraceSummary(map[string]any{"available": true, "requested": false, "active": false, "coverage": "incomplete", "received": 7, "queue_dropped": 2, "unregister_failed": true, "error": "PNP_UNREGISTER_FAILED", "recent": []string{"node-key"}}))
	var got map[string]any
	if err != nil || json.Unmarshal(b, &got) != nil || got["queue_dropped"] != float64(2) || got["unregister_failed"] != true || got["received"] != float64(7) || got["error"] != "PNP_UNREGISTER_FAILED" || got["recent"] != nil {
		t.Fatal(string(b), err)
	}
}
