//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const connectionTimingDelay = 12 * time.Second

type connectionTimingSnapshot struct {
	SelectedUTC      string `json:"selected_utc,omitempty"`
	SelectedMS       int64  `json:"selected_ms"`
	CounterSemantics string `json:"counter_semantics"`

	RunID              string `json:"run_id,omitempty"`
	WaitBeginMS        int64  `json:"owner_wait_begin_ms"`
	WakeMS             int64  `json:"owner_wake_ms"`
	DelayBeginMS       int64  `json:"delay_begin_ms"`
	PresenceAcceptedMS int64  `json:"presence_accepted_ms"`
	AttemptStartMS     int64  `json:"attempt_start_ms"`
	SharedHostBeginMS  int64  `json:"shared_host_wait_begin_ms"`
	SharedHostEndMS    int64  `json:"shared_host_wait_end_ms"`
	NativeNoticeMS     int64  `json:"native_notice_ms"`

	Available           bool   `json:"available"`
	Mode                string `json:"mode"`
	Phase               string `json:"phase"`
	SavedMode           string `json:"saved_mode"`
	Persistence         string `json:"persistence"`
	PersistenceError    string `json:"persistence_error,omitempty"`
	WaitBeginUTC        string `json:"owner_wait_begin_utc,omitempty"`
	WakeUTC             string `json:"owner_wake_utc,omitempty"`
	WakeReason          string `json:"owner_wake_reason,omitempty"`
	WakeCount           uint64 `json:"owner_wake_count"`
	DelayBeginUTC       string `json:"delay_begin_utc,omitempty"`
	PresenceAcceptedUTC string `json:"presence_accepted_utc,omitempty"`
	AttemptStartUTC     string `json:"attempt_start_utc,omitempty"`
	SharedHostBeginUTC  string `json:"shared_host_wait_begin_utc,omitempty"`
	SharedHostEndUTC    string `json:"shared_host_wait_end_utc,omitempty"`
	NativeRegistration  string `json:"native_registration,omitempty"`
	NativeNoticeUTC     string `json:"native_notice_utc,omitempty"`
	NativeNoticeCount   uint64 `json:"native_notice_count"`
	NativeNoticeCode    uint32 `json:"native_notice_code,omitempty"`
	NativeNoticeSource  string `json:"native_notice_source,omitempty"`
}

type connectionTimingController struct {
	stamp                func(time.Time) (string, int64)
	mu                   sync.Mutex
	state                connectionTimingSnapshot
	revision             uint64
	changed              chan struct{}
	persistenceIO        sync.Mutex
	saveMode             func(string) error
	restoreMode          func() (string, error)
	persistenceOperation uint64
	selectionRevision    uint64
	restoreAllowed       bool
	persistenceKnown     bool
}

func (c *connectionTimingController) initLocked() {
	if c.changed == nil {
		c.changed = make(chan struct{})
		c.state.Mode = "normal"
		c.state.SavedMode = "normal"
		c.state.Persistence = "unknown"
		c.state.Phase = "normal"
		c.state.SelectedMS = -1
		c.state.CounterSemantics = "process_cumulative_owner_wakes_and_delivered_native_hints_not_reenumeration_proof"
		c.state.WaitBeginMS = -1
		c.state.WakeMS = -1
		c.state.DelayBeginMS = -1
		c.state.PresenceAcceptedMS = -1
		c.state.AttemptStartMS = -1
		c.state.SharedHostBeginMS = -1
		c.state.SharedHostEndMS = -1
		c.state.NativeNoticeMS = -1
	}
}
func (c *connectionTimingController) msLocked(now time.Time) int64 {
	if c.stamp == nil {
		return -1
	}
	run, ms := c.stamp(now)
	if run != "" {
		c.state.RunID = run
	}
	return ms
}
func timingUTC(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func (c *connectionTimingController) resetLocked(phase string) {
	c.initLocked()
	close(c.changed)
	c.changed = make(chan struct{})
	c.revision++
	c.state.Mode = "normal"
	c.state.Phase = phase
}
func (c *connectionTimingController) set(mode string, now time.Time) error {
	if mode != "normal" && mode != "fast" && mode != "delayed" {
		return fmt.Errorf("CONNECTION_TIMING_MODE_INVALID")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setLocked(mode, now)
}
func (c *connectionTimingController) setLocked(mode string, now time.Time) error {
	c.resetLocked("normal")
	if mode == "normal" {
		return nil
	}
	c.state.Mode = mode
	c.state.Phase = "armed"

	c.state.SelectedUTC = timingUTC(now)
	c.state.SelectedMS = c.msLocked(now)
	c.state.WaitBeginUTC = ""
	c.state.WaitBeginMS = -1
	c.state.WakeUTC = ""
	c.state.WakeMS = -1
	c.state.WakeReason = ""
	c.state.DelayBeginUTC = ""
	c.state.DelayBeginMS = -1
	c.state.PresenceAcceptedUTC = ""
	c.state.PresenceAcceptedMS = -1
	c.state.AttemptStartUTC = ""
	c.state.AttemptStartMS = -1
	c.state.SharedHostBeginUTC = ""
	c.state.SharedHostBeginMS = -1
	c.state.SharedHostEndUTC = ""
	c.state.SharedHostEndMS = -1
	c.state.NativeNoticeUTC = ""
	c.state.NativeNoticeMS = -1
	c.state.NativeNoticeCode = 0
	c.state.NativeNoticeSource = ""
	return nil
}
func (c *connectionTimingController) plan(_ time.Time) connectionTimingPlan {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	p := connectionTimingPlan{revision: c.revision, mode: c.state.Mode, fallback: 30 * time.Second, changed: c.changed}
	if c.state.Mode != "normal" {
		p.fallback = time.Second
		if c.state.Mode == "delayed" {
			p.delay = connectionTimingDelay
		}
	}
	return p
}
func (c *connectionTimingController) snapshot() connectionTimingSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	return c.state
}
func (c *connectionTimingController) waitBegin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	now := time.Now()
	c.state.WaitBeginMS = c.msLocked(now)
	c.state.WaitBeginUTC = timingUTC(now)
}
func (c *connectionTimingController) ownerLoop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	if c.state.WaitBeginUTC == "" {
		now := time.Now()
		c.state.WaitBeginUTC = timingUTC(now)
		c.state.WaitBeginMS = c.msLocked(now)
	}
}
func (c *connectionTimingController) wake(reason string) {
	switch reason {
	case "context_cancelled", "owner_notice", "fallback", "profile_changed", "delay_complete", "presence_unreadable", "presence_changed":
	default:
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	now := time.Now()
	c.state.WakeMS = c.msLocked(now)
	c.state.WakeUTC = timingUTC(now)
	c.state.WakeReason = reason
	c.state.WakeCount++
}
func (c *connectionTimingController) stage(stage string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	at := time.Now()
	now := timingUTC(at)
	ms := c.msLocked(at)
	switch stage {
	case "shared_host_wait_begin":
		c.state.SharedHostBeginUTC = now
		c.state.SharedHostBeginMS = ms
	case "shared_host_wait_end":
		c.state.SharedHostEndUTC = now
		c.state.SharedHostEndMS = ms
	case "attempt_started":
		c.state.AttemptStartUTC = now
		c.state.AttemptStartMS = ms
	case "notification_subscribed":
		c.state.NativeRegistration = "subscribed"
	case "notification_unavailable":
		c.state.NativeRegistration = "unavailable"
	}
}
func (c *connectionTimingController) nativeNotice(code uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	now := time.Now()
	c.state.NativeNoticeMS = c.msLocked(now)
	c.state.NativeNoticeUTC = timingUTC(now)
	c.state.NativeNoticeCode = code
	c.state.NativeNoticeSource = "device_instance_hint"
	if code == 1 {
		c.state.NativeNoticeSource = "usb_interface_hint"
	}
	c.state.NativeNoticeCount++
}

// Readiness here is only a cached candidate, never native identity authority.
// A delayed candidate is re-read after the timer and matched privately; none of
// its identifiers enter the bounded diagnostic snapshot.
func (c *connectionTimingController) accept(ctx context.Context, p connectionTimingPlan, kind string, initial idlePresence, read func(context.Context) (string, idlePresence), wait func(context.Context, time.Duration, <-chan struct{}) string, allowed ...func() bool) (string, idlePresence, bool) {
	if ctx.Err() != nil || !initial.readable || !initial.candidate || initial.identity == "" {
		return "", idlePresence{}, false
	}
	if p.delay > 0 {
		c.mu.Lock()
		if c.revision != p.revision {
			c.mu.Unlock()
			return "", idlePresence{}, false
		}
		c.state.Phase = "delaying"
		now := time.Now()
		c.state.DelayBeginMS = c.msLocked(now)
		c.state.DelayBeginUTC = timingUTC(now)
		c.mu.Unlock()
		reason := wait(ctx, p.delay, p.changed)
		c.mu.Lock()
		if c.revision == p.revision {
			c.state.Phase = "armed"
		}
		c.mu.Unlock()
		c.wake(reason)
		if reason != "delay_complete" || ctx.Err() != nil {
			return "", idlePresence{}, false
		}
		freshKind, fresh := read(ctx)
		if !fresh.readable {
			c.wake("presence_unreadable")
			return "", idlePresence{}, false
		}
		if !fresh.candidate || fresh.identity != initial.identity || freshKind != kind {
			c.wake("presence_changed")
			return "", idlePresence{}, false
		}
		initial = fresh
	}
	if len(allowed) > 0 && !allowed[0]() {
		return "", idlePresence{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || c.revision != p.revision {
		return "", idlePresence{}, false
	}
	now := time.Now()
	c.state.PresenceAcceptedMS = c.msLocked(now)
	c.state.PresenceAcceptedUTC = timingUTC(now)
	if c.state.Mode != "normal" {
		c.state.Phase = "accepted"
	}
	return kind, initial, true
}
func waitConnectionTimingDelay(ctx context.Context, d time.Duration, changed <-chan struct{}) string {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return "context_cancelled"
	case <-changed:
		return "profile_changed"
	case <-timer.C:
		return "delay_complete"
	}
}
