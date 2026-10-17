package ipadncm

import (
	"encoding/json"
	"fmt"
	"sync"
)

type ServiceDisplaySnapshot struct {
	Desktop     any                          `json:"desktop"`
	Connections map[string]ApplicationResult `json:"connections"`
	Events      []any                        `json:"events,omitempty"`
}

var desktopSnapshotObservation struct {
	sync.Mutex
	Status string `json:"status"`
	Bytes  int    `json:"bytes"`
	Reads  uint64 `json:"reads"`
}

func DesktopSnapshotDiagnostics() any {
	desktopSnapshotObservation.Lock()
	defer desktopSnapshotObservation.Unlock()
	return struct {
		Status string `json:"status"`
		Bytes  int    `json:"bytes"`
		Reads  uint64 `json:"reads"`
	}{desktopSnapshotObservation.Status, desktopSnapshotObservation.Bytes, desktopSnapshotObservation.Reads}
}

// The desktop uses current values and aggregates, never the per-second history.
// Keep full history in the core; do not let session duration grow the IPC payload.
func desktopApplicationResult(r ApplicationResult) ApplicationResult {
	r.Performance.HistoryOmitted += uint64(len(r.Performance.History))
	r.Performance.History = nil
	r.Performance.FaultEvents = nil
	return r
}

func encodeServiceDisplaySnapshot(s ServiceDisplaySnapshot) ([]byte, error) {
	projected := make(map[string]ApplicationResult, len(s.Connections))
	for device, r := range s.Connections {
		projected[device] = desktopApplicationResult(r)
	}
	s.Connections = projected
	b, err := json.Marshal(s)
	status := "ok"
	if err != nil {
		status = "encode_failed"
	} else if len(b) > 48<<10 {
		status = "payload_too_large"
	}
	desktopSnapshotObservation.Lock()
	desktopSnapshotObservation.Status, desktopSnapshotObservation.Bytes = status, len(b)
	desktopSnapshotObservation.Reads++
	desktopSnapshotObservation.Unlock()
	if status != "ok" {
		return nil, fmt.Errorf("CORE_DESKTOP_STATUS_TOO_LARGE")
	}
	return b, nil
}

func desktopReadErrorCode(err error) string {
	if err == nil {
		return "CORE_DESKTOP_RESPONSE_INVALID"
	}
	switch err.Error() {
	case "CORE_VERSION_CHANGED", "CORE_DESKTOP_STATUS_TOO_LARGE", "CORE_SNAPSHOT_LIMIT", "CORE_MONITOR_INITIALIZING", "CORE_INITIALIZING", "CORE_IPC_PEER_REJECTED", "CORE_IPC_RESPONSE_INVALID":
		return err.Error()
	default:
		return "CORE_UI_READ_FAILED"
	}
}
