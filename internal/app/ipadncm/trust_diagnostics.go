package ipadncm

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"suhang/usbnet/internal/buildinfo"
)

const trustEventLimit = 20
const trustNodeLimit = 4

type TrustDiagnosticEvent struct {
	MS      int64  `json:"ms_since_observer_start"`
	UTC     string `json:"utc"`
	Attempt uint64 `json:"software_attempt"`
	Source  string `json:"source"`
	Kind    string `json:"kind"`
	Data    string `json:"data,omitempty"`
}

type trustNodeState struct {
	Role     string `json:"role"`
	Service  string `json:"service"`
	Problem  uint32 `json:"problem"`
	Readable bool   `json:"cm_readable"`
	Started  bool   `json:"started"`
	Restart  bool   `json:"restart_required"`
}
type trustPNPState struct {
	Read     string           `json:"read"`
	Roots    int              `json:"roots"`
	Controls int              `json:"controls"`
	Nodes    []trustNodeState `json:"nodes"`
	Omitted  int              `json:"nodes_omitted"`
}
type trustServiceState struct {
	Read  string `json:"read"`
	State uint32 `json:"state"`
	PID   uint32 `json:"pid"`
}

type TrustDiagnosticSnapshot struct {
	Schema                 int                    `json:"schema"`
	RunID                  string                 `json:"run_id"`
	StartedUTC             string                 `json:"started_utc"`
	Active                 bool                   `json:"active"`
	NotificationStatus     string                 `json:"notification_subscription"`
	NotificationSemantics  string                 `json:"notification_semantics"`
	MarkerSemantics        string                 `json:"marker_semantics"`
	IPadPromptObserved     bool                   `json:"ipad_prompt_observed"`
	PairingRequestObserved bool                   `json:"pairing_request_observed"`
	SampleIntervalMS       int                    `json:"sample_interval_ms"`
	LastPNPSampleUTC       string                 `json:"last_pnp_sample_utc,omitempty"`
	LastPNPSampleMS        int64                  `json:"last_pnp_sample_ms"`
	LastAMDSSampleUTC      string                 `json:"last_amds_sample_utc,omitempty"`
	LastAMDSSampleMS       int64                  `json:"last_amds_sample_ms"`
	SuppressedNoticeHints  uint64                 `json:"received_notice_hints_suppressed"`
	NodeEncoding           string                 `json:"node_event_encoding"`
	Events                 []TrustDiagnosticEvent `json:"events"`
	Dropped                uint64                 `json:"events_omitted"`
	PNPFailures            uint64                 `json:"pnp_sample_failures"`
	ServiceFailures        uint64                 `json:"amds_query_failures"`
	PNP                    *trustPNPState         `json:"latest_pnp,omitempty"`
	AMDS                   *trustServiceState     `json:"latest_amds,omitempty"`
}

type trustDiagnosticState struct {
	sync.Mutex
	started     time.Time
	result      TrustDiagnosticSnapshot
	pnpKey      string
	serviceSeen bool
	// The sink is memory-only and must not acquire the observer lock or clock.
	archive func(TrustDiagnosticEvent)
}

var trustDiagnostics = &trustDiagnosticState{archive: func(e TrustDiagnosticEvent) {
	RecordConnectionArchiveEvent("trust_event", e)
}}

func (m *trustDiagnosticState) start(now time.Time, runID string) bool {
	m.Lock()
	defer m.Unlock()
	if !m.started.IsZero() {
		return false
	}
	m.started = now
	m.result = TrustDiagnosticSnapshot{Schema: 1, RunID: runID, StartedUTC: now.UTC().Format(time.RFC3339Nano), Active: true,
		NotificationStatus: "pending", NotificationSemantics: "apple_mobile_delivery_hint;source_coalescing_count_unknown;not_reenumeration_or_prompt_proof",
		MarkerSemantics:  "user_recorded_time_not_observed_iPad_prompt_timestamp",
		SampleIntervalMS: 1000,
		NodeEncoding:     "role/service/problem/readable/started/restart; R=root,00=MI00(photo_candidate),01=MI01(Apple_transport); C=usbccgp,N=UsbNcm,A=Apple,W=WinUSB,P=WUDFWpdMtp,F=WUDFRd,S=usbscan,X=none,U=other",
		Events:           make([]TrustDiagnosticEvent, 0, trustEventLimit)}
	m.appendLocked(now, 0, "observer", "started", "")
	return true
}

func (m *trustDiagnosticState) appendLocked(now time.Time, attempt uint64, source, kind, data string) {
	if !m.result.Active {
		return
	}
	if len(data) > 160 {
		data = data[:160]
	}
	if len(m.result.Events) == trustEventLimit {
		copy(m.result.Events, m.result.Events[1:])
		m.result.Events = m.result.Events[:trustEventLimit-1]
		m.result.Dropped++
	}
	ms := now.Sub(m.started).Milliseconds()
	if ms < 0 {
		ms = 0
	}
	event := TrustDiagnosticEvent{MS: ms, UTC: now.UTC().Format("2006-01-02T15:04:05.000Z"), Attempt: attempt, Source: source, Kind: kind, Data: data}
	m.result.Events = append(m.result.Events, event)
	if m.archive != nil {
		m.archive(event)
	}
}

func (m *trustDiagnosticState) event(now time.Time, attempt uint64, source, kind, data string) {
	m.Lock()
	defer m.Unlock()
	m.appendLocked(now, attempt, source, kind, data)
}

func trustObservationCode(s string) string {
	switch s {
	case "ok", "access_denied", "not_installed", "timeout", "cancelled", "query_failed", "enumeration_limit", "invalid_state", "unavailable":
		return s
	}
	return "query_failed"
}

func normalizeTrustPNP(p trustPNPState) trustPNPState {
	p.Read = trustObservationCode(p.Read)
	if p.Read != "ok" {
		return trustPNPState{Read: p.Read}
	}
	nodes := append([]trustNodeState(nil), p.Nodes...)
	for i := range nodes {
		switch nodes[i].Role {
		case "R", "00", "01", "02", "04", "03", "05":
		default:
			nodes[i].Role = "other"
		}
		switch nodes[i].Service {
		case "C", "N", "A", "W", "P", "F", "S", "X":
		default:
			nodes[i].Service = "U"
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		if a, b := trustNodePriority(nodes[i]), trustNodePriority(nodes[j]); a != b {
			return a < b
		}
		return trustNodeCode(nodes[i]) < trustNodeCode(nodes[j])
	})
	p.Omitted = max(0, p.Omitted)
	if len(nodes) > trustNodeLimit {
		p.Omitted += len(nodes) - trustNodeLimit
		// Reserve one slot for each relevant role before duplicate nodes. The
		// observer covers all roots; a second device must not hide MI01 or NCM.
		selected := make([]trustNodeState, 0, trustNodeLimit)
		used := make([]bool, len(nodes))
		for _, category := range []int{0, 1, 2, 3} {
			for i, n := range nodes {
				rank := trustNodePriority(n)
				if rank == category || category == 3 && rank == 4 {
					selected, used[i] = append(selected, n), true
					break
				}
			}
		}
		for i, n := range nodes {
			if len(selected) == trustNodeLimit {
				break
			}
			if !used[i] {
				selected = append(selected, n)
			}
		}
		nodes = selected
	}
	p.Nodes = nodes
	p.Roots, p.Controls = max(0, min(p.Roots, 4096)), max(0, min(p.Controls, 4096))
	return p
}

func trustNodePriority(n trustNodeState) int {
	switch n.Role {
	case "R":
		return 0
	case "00":
		return 1
	case "01":
		return 2
	}
	if n.Service == "N" {
		if n.Readable && n.Started && n.Problem == 0 && !n.Restart {
			return 3
		}
		return 4
	}
	return 5
}

func trustNodeCode(n trustNodeState) string {
	return fmt.Sprintf("%s/%s/%d/%d/%d/%d", n.Role, n.Service, n.Problem, trustBool(n.Readable), trustBool(n.Started), trustBool(n.Restart))
}
func trustBool(v bool) int {
	if v {
		return 1
	}
	return 0
}
func trustPNPKey(p trustPNPState) string {
	if p.Read != "ok" {
		return "read=" + p.Read
	}
	parts := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		parts = append(parts, trustNodeCode(n))
	}
	return fmt.Sprintf("r=%d;c=%d;n=%s;omitted=%d", p.Roots, p.Controls, strings.Join(parts, ","), p.Omitted)
}

func (m *trustDiagnosticState) pnp(now time.Time, attempt uint64, p trustPNPState) {
	p = normalizeTrustPNP(p)
	key := trustPNPKey(p)
	m.Lock()
	defer m.Unlock()
	if !m.result.Active {
		return
	}
	m.result.LastPNPSampleUTC = now.UTC().Format("2006-01-02T15:04:05.000Z")
	m.result.LastPNPSampleMS = max(int64(0), now.Sub(m.started).Milliseconds())
	if p.Read != "ok" {
		m.result.PNPFailures++
	}
	if m.result.PNP != nil && m.pnpKey == key {
		return
	}
	kind := "node_state_changed"
	if m.result.PNP == nil {
		kind = "first_sample"
	}
	if p.Read != "ok" {
		kind = "sample_failed"
	}
	m.result.PNP = &p
	m.pnpKey = key
	m.appendLocked(now, attempt, "pnp_sample", kind, key)
}

func (m *trustDiagnosticState) amds(now time.Time, attempt uint64, s trustServiceState) {
	s.Read = trustObservationCode(s.Read)
	if s.Read != "ok" {
		s.State, s.PID = 0, 0
	}
	m.Lock()
	defer m.Unlock()
	if !m.result.Active {
		return
	}
	m.result.LastAMDSSampleUTC = now.UTC().Format("2006-01-02T15:04:05.000Z")
	m.result.LastAMDSSampleMS = max(int64(0), now.Sub(m.started).Milliseconds())
	if s.Read != "ok" {
		m.result.ServiceFailures++
	}
	if m.serviceSeen && *m.result.AMDS == s {
		return
	}
	kind := "state_or_pid_changed"
	if !m.serviceSeen {
		kind = "first_sample"
	}
	if s.Read != "ok" {
		kind = "query_failed"
	}
	m.serviceSeen = true
	m.result.AMDS = &s
	m.appendLocked(now, attempt, "amds_query", kind, fmt.Sprintf("read=%s;state=%d;pid=%d", s.Read, s.State, s.PID))
}

func (m *trustDiagnosticState) suppressNoticeHint() {
	m.Lock()
	defer m.Unlock()
	if m.result.Active {
		m.result.SuppressedNoticeHints++
	}
}

func (m *trustDiagnosticState) subscription(now time.Time, attempt uint64, status string) {
	if status != "subscribed" {
		status = "unavailable_polling_continues"
	}
	m.Lock()
	defer m.Unlock()
	if !m.result.Active {
		return
	}
	m.result.NotificationStatus = status
	m.appendLocked(now, attempt, "observer", "notification_subscription", status)
}
func (m *trustDiagnosticState) stop(now time.Time, attempt uint64) {
	m.Lock()
	defer m.Unlock()
	m.appendLocked(now, attempt, "observer", "stopped", "")
	m.result.Active = false
}
func (m *trustDiagnosticState) snapshot() TrustDiagnosticSnapshot {
	m.Lock()
	defer m.Unlock()
	r := m.result
	r.Events = append([]TrustDiagnosticEvent(nil), r.Events...)
	if r.PNP != nil {
		p := *r.PNP
		p.Nodes = append([]trustNodeState(nil), p.Nodes...)
		r.PNP = &p
	}
	if r.AMDS != nil {
		s := *r.AMDS
		r.AMDS = &s
	}
	return r
}

func TrustDiagnosticsSnapshot() TrustDiagnosticSnapshot { return trustDiagnostics.snapshot() }

func RecordTrustPromptMarker(which int) {
	if buildinfo.LocalDiagnostics != "true" || (which != 1 && which != 2) {
		return
	}
	trustDiagnostics.event(time.Now(), currentSoftwareAttempt(), "user_marker", fmt.Sprintf("prompt_%d_recorded", which), "")
}

// The caller already owns the attempt number and releases its monitor lock.
func RecordTrustOperation(attempt uint64, stage string) {
	if buildinfo.LocalDiagnostics != "true" {
		return
	}
	switch stage {
	case "usb_control_open_begin", "usb_control_open_end", "usb_get_mode_begin", "usb_get_mode_end", "usb_set_mode_request_begin", "usb_set_mode_request_end":
		trustDiagnostics.event(time.Now(), attempt, "own_operation", stage, "")
	case "usb_mode_switch_begin", "usb_mode_switch_end", "grouping_write_begin", "grouping_write_end", "device_restart_begin", "device_restart_end", "grouping_restore_begin", "grouping_restore_end", "apple_service_lease_begin", "apple_service_lease_end", "native_start_check_begin", "native_start_check_end":
		trustDiagnostics.event(time.Now(), attempt, "own_operation", stage, "")
	}
}

// stamp shares the observer's monotonic origin without adding a trust event.
// -1 distinguishes a timestamp captured before observer initialization.
func (m *trustDiagnosticState) stamp(now time.Time) (string, int64) {
	m.Lock()
	defer m.Unlock()
	if m.started.IsZero() {
		return "", -1
	}
	return m.result.RunID, max(int64(0), now.Sub(m.started).Milliseconds())
}
