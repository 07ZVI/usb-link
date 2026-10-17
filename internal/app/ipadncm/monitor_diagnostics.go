package ipadncm

import (
	"sync"
	"time"
)

type DeviceNotice struct {
	ElapsedMS int64  `json:"elapsed_ms"`
	Class     string `json:"windows_device_notice_class"`
	Operation string `json:"own_operation_time_correlation_not_causal_proof,omitempty"`
}
type MonitorDiagnostics struct {
	ElapsedMS                int64             `json:"monitor_elapsed_ms"`
	Attempts                 uint64            `json:"connection_attempts"`
	AutomaticRetries         uint64            `json:"automatic_retry_attempts"`
	LastAutomaticRetryReason string            `json:"last_automatic_retry_reason,omitempty"`
	ManualRetries            uint64            `json:"manual_retry_requests"`
	DeviceNotices            uint64            `json:"windows_device_change_notifications_not_physical_unplug_count"`
	DroppedNotices           uint64            `json:"earlier_notifications_omitted"`
	NoticeSamples            []DeviceNotice    `json:"latest_device_notice_samples,omitempty"`
	PresenceReads            uint64            `json:"idle_pnp_cache_reads"`
	PresentSamples           uint64            `json:"idle_unique_ipad_candidate_samples"`
	AbsentSamples            uint64            `json:"idle_no_apple_mobile_root_samples"`
	UnknownSamples           uint64            `json:"idle_unreadable_or_ambiguous_samples"`
	ConnectionTrace          []ConnectionEvent `json:"latest_ipad_connection_stage_events,omitempty"`
	DroppedConnectionEvents  uint64            `json:"connection_stage_events_omitted"`
}
type monitorDiagnosticCounter struct {
	sync.Mutex
	started         time.Time
	r               MonitorDiagnostics
	attemptStarted  time.Time
	attempt         uint64
	deviceKind      string
	operation       string
	operationAt     time.Time
	operationActive bool
}

func newMonitorDiagnosticCounter() *monitorDiagnosticCounter {
	return &monitorDiagnosticCounter{started: time.Now()}
}

var monitorDiagnostics = newMonitorDiagnosticCounter()

func (m *monitorDiagnosticCounter) notice(code uint32) {
	kind := "OTHER_DEVICE_CHANGE"
	switch code {
	case 7:
		kind = "DEVICE_NODES_CHANGED"
	case 0x8000:
		kind = "DEVICE_ARRIVAL_NOTICE"
	case 0x8004:
		kind = "DEVICE_REMOVAL_NOTICE"
	}
	m.Lock()
	defer m.Unlock()
	m.r.DeviceNotices++
	if len(m.r.NoticeSamples) == 64 {
		m.r.NoticeSamples = m.r.NoticeSamples[1:]
		m.r.DroppedNotices++
	}
	op := ""
	if m.deviceKind == "iPad" && m.operation != "" && (m.operationActive || time.Since(m.operationAt) <= 2*time.Second) {
		op = m.operation
	}
	m.r.NoticeSamples = append(m.r.NoticeSamples, DeviceNotice{ElapsedMS: time.Since(m.started).Milliseconds(), Class: kind, Operation: op})
}
func (m *monitorDiagnosticCounter) presence(p idlePresence) {
	m.Lock()
	defer m.Unlock()
	m.r.PresenceReads++
	switch {
	case !p.readable:
		m.r.UnknownSamples++
	case p.absent:
		m.r.AbsentSamples++
	case p.candidate:
		m.r.PresentSamples++
	default:
		m.r.UnknownSamples++
	}
}
func (m *monitorDiagnosticCounter) snapshot() MonitorDiagnostics {
	m.Lock()
	defer m.Unlock()
	r := m.r
	r.ElapsedMS = time.Since(m.started).Milliseconds()
	r.NoticeSamples = append([]DeviceNotice(nil), r.NoticeSamples...)
	r.ConnectionTrace = append([]ConnectionEvent(nil), r.ConnectionTrace...)
	return r
}
func ConnectionMonitorDiagnostics() MonitorDiagnostics { return monitorDiagnostics.snapshot() }
func RecordConnectionAttempt() {
	RecordConnectionAttemptFor("")
}
func RecordConnectionAttemptFor(kind string) {
	monitorDiagnostics.Lock()
	monitorDiagnostics.r.Attempts++
	monitorDiagnostics.attempt++
	monitorDiagnostics.deviceKind = kind
	monitorDiagnostics.attemptStarted = time.Now()
	monitorDiagnostics.operation = ""
	monitorDiagnostics.operationActive = false
	attempt := monitorDiagnostics.attempt
	monitorDiagnostics.Unlock()
	if kind == "iPad" {
		RecordConnectionArchiveAttempt(attempt)
		RequestConnectionEnvironmentCapture()
	}
}
func recordManualRetry() {
	monitorDiagnostics.Lock()
	monitorDiagnostics.r.ManualRetries++
	monitorDiagnostics.Unlock()
}

func recordAutomaticRetry(reason string) {
	monitorDiagnostics.Lock()
	defer monitorDiagnostics.Unlock()
	monitorDiagnostics.r.AutomaticRetries++
	monitorDiagnostics.r.LastAutomaticRetryReason = reason
}
