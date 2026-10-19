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

// Controls need authoritative preference and recovery state. Descriptor/event
// arrays remain once in Detail instead of doubling the limited IPC payload.
func desktopExperimentControl(value any) any {
	b, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var source map[string]json.RawMessage
	if json.Unmarshal(b, &source) != nil {
		return nil
	}
	if source == nil {
		return nil
	}
	result := map[string]json.RawMessage{}
	for _, key := range []string{"available", "requested", "effective", "busy", "persistence", "saved_enabled", "request_id", "rejected_id", "rejected_error", "phase", "error", "cause_code", "native_code", "policy_armed", "restore_requires_reenumeration", "recovery_required", "retained_on_exit", "capture_mode", "provider_coverage", "enabled_provider_count", "ordinary_ipv4_network_ready", "mode_requested", "observed_configuration", "observed_target_matched"} {
		if v, ok := source[key]; ok {
			result[key] = v
		}
	}
	return result
}

// Keep event samples and provider details in diagnostics, not the UI envelope.
func desktopUSBTraceSummary(value any) any {
	b, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var source map[string]json.RawMessage
	if json.Unmarshal(b, &source) != nil || source == nil {
		return nil
	}
	if string(source["available"]) == "false" && string(source["phase"]) == `"local_build_required"` {
		return nil
	}
	result := map[string]json.RawMessage{}
	for _, key := range []string{"available", "requested", "active", "phase", "error", "coverage", "target_scope", "started_utc", "last_event_utc", "stopped_utc", "received", "accepted", "queue_overflow", "schema_rejected", "events_lost", "realtime_buffers_lost", "queue_dropped", "unregister_failed", "archive_rejected", "late_events", "timestamp_unknown", "cancelled_events", "cancelled_starts", "cancelled_before_ready", "cancelled_start_queue_dropped", "subscriptions_ready_utc", "rejected", "rejected_size", "rejected_instance_metadata", "rejected_interface_metadata", "query_ownership", "first_query_failure"} {
		if v, ok := source[key]; ok {
			result[key] = v
		}
	}
	for _, key := range []string{"received_semantics", "callbacks_received", "session_metadata_callbacks", "session_header_callbacks", "unknown_provider_callbacks", "invalid_header_callbacks", "known_provider_shape_rejected", "known_provider_template_rejected", "known_provider_scalar_rejected", "rejected_header_count", "rejected_header_signatures_omitted"} {
		if v, ok := source[key]; ok {
			result[key] = v
		}
	}
	return result
}

var desktopSnapshotObservation struct {
	sync.Mutex
	Status  string `json:"status"`
	Bytes   int    `json:"bytes"`
	Reads   uint64 `json:"reads"`
	Trimmed uint64 `json:"trimmed_for_pipe_limit"`
}

func DesktopSnapshotDiagnostics() any {
	desktopSnapshotObservation.Lock()
	defer desktopSnapshotObservation.Unlock()
	return struct {
		Status  string `json:"status"`
		Bytes   int    `json:"bytes"`
		Reads   uint64 `json:"reads"`
		Trimmed uint64 `json:"trimmed_for_pipe_limit"`
	}{desktopSnapshotObservation.Status, desktopSnapshotObservation.Bytes, desktopSnapshotObservation.Reads, desktopSnapshotObservation.Trimmed}
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

// The pipe and the core report specific codes; only text that is not a stable
// code stays opaque so a native message or path cannot reach the window.
func desktopReadErrorCode(err error) string {
	if err == nil {
		return "CORE_DESKTOP_RESPONSE_INVALID"
	}
	code, _, _ := CoreLinkErrorCode(err)
	return code
}

// The display envelope is measured before the service adds dependency,
// internet and exit state, and before the other snapshot sections join it.
// Over the pipe limit, long text is cut first so the window keeps reading
// instead of failing on one oversized diagnostic string.
func TrimDisplayForTransport(display json.RawMessage, excess int) (json.RawMessage, bool) {
	var tree any
	if json.Unmarshal(display, &tree) != nil {
		return display, false
	}
	goal := len(display) - excess
	if envelope, ok := tree.(map[string]any); ok {
		delete(envelope, "events")
	}
	for _, limit := range []int{4096, 1024, 256, 64} {
		tree = truncateJSONStrings(tree, limit)
		b, err := json.Marshal(tree)
		if err == nil && len(b) <= goal {
			desktopSnapshotObservation.Lock()
			desktopSnapshotObservation.Trimmed++
			desktopSnapshotObservation.Unlock()
			return b, true
		}
	}
	return display, false
}

func truncateJSONStrings(v any, limit int) any {
	switch t := v.(type) {
	case string:
		if len(t) > limit {
			cut := limit
			for cut > 0 && t[cut]&0xC0 == 0x80 {
				cut--
			}
			return t[:cut] + "…"
		}
	case []any:
		for i := range t {
			t[i] = truncateJSONStrings(t[i], limit)
		}
	case map[string]any:
		for k, e := range t {
			t[k] = truncateJSONStrings(e, limit)
		}
	}
	return v
}
