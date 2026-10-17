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
