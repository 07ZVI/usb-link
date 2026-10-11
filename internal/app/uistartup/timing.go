// Package uistartup carries display-only launch measurements. These records
// never establish USB readiness, process ownership, consent or upgrade health.
package uistartup

import (
	"sync"
	"time"
)

type Timing struct {
	Request   string `json:"request"`
	Stage     string `json:"stage"`
	ElapsedUS uint64 `json:"elapsed_us"`
}

func Valid(t Timing) bool {
	if len(t.Request) != 32 || t.ElapsedUS == 0 || t.ElapsedUS > 600_000_000 {
		return false
	}
	for _, c := range t.Request {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	switch t.Stage {
	case "login-source-verified", "login-self-source-pinned", "login-service-start-verified", "login-service-bound", "show-request", "payload-verified", "renderer-started", "renderer-opened", "existing-renderer-show-queued", "renderer-main", "renderer-app-initialize", "renderer-theme-ready", "renderer-dashboard-create", "renderer-dashboard-ready", "renderer-first-managed-draw":
		return true
	}
	return false
}

// Queue piggybacks bounded observations on the existing authenticated snapshot
// request. It adds no timer, extra IPC call or polling while the UI is closed.
type Queue struct {
	mu      sync.Mutex
	records []Timing
}

func (q *Queue) Add(t Timing) {
	if !Valid(t) {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.records) == 32 {
		q.records = q.records[1:]
	}
	q.records = append(q.records, t)
}
func (q *Queue) Take() []Timing {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.records
	q.records = nil
	return out
}
func (q *Queue) Restore(ts []Timing) {
	for _, t := range ts {
		q.Add(t)
	}
}

type Observation struct {
	Timing
	ObservedUTC string `json:"observed_utc"`
	UIPID       uint32 `json:"ui_pid"`
	UICreation  uint64 `json:"ui_creation"`
	Scope       string `json:"scope"`
}

var history struct {
	sync.Mutex
	records []Observation
	total   uint64
}

// The caller supplies PID/creation from the authenticated local pipe peer;
// client payloads can report timings but cannot choose their process identity.
func Record(ts []Timing, pid uint32, creation uint64) bool {
	if len(ts) == 0 {
		return true
	}
	if pid == 0 || creation == 0 || len(ts) > 32 {
		return false
	}
	for _, t := range ts {
		if !Valid(t) {
			return false
		}
	}
	history.Lock()
	defer history.Unlock()
	for _, t := range ts {
		if len(history.records) == 128 {
			history.records = history.records[1:]
		}
		history.total++
		history.records = append(history.records, Observation{t, time.Now().UTC().Format(time.RFC3339Nano), pid, creation, "UI_REPORTED_MONOTONIC_STAGE_NOT_FIRST_PAINT_OR_NETWORK_READY"})
	}
	return true
}
func Snapshot() any {
	history.Lock()
	defer history.Unlock()
	return struct {
		Total   uint64        `json:"total"`
		Records []Observation `json:"records"`
	}{history.total, append([]Observation(nil), history.records...)}
}

// RendererStage is a display-only whitelist, separate from any product action.
func RendererStage(stage string) bool {
	switch stage {
	case "renderer-main", "renderer-app-initialize", "renderer-theme-ready", "renderer-dashboard-create", "renderer-dashboard-ready", "renderer-first-managed-draw":
		return true
	}
	return false
}
