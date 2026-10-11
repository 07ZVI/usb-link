// Package startuptelemetry records observation times, not connection authority.
// Login, kernel uptime, process creation, USB presence and readiness are separate.
package startuptelemetry

import (
	"sync"
	"time"
)

type Anchor struct {
	Available bool       `json:"available"`
	At        *time.Time `json:"utc,omitempty"`
	Source    string     `json:"source"`
	Problem   string     `json:"problem,omitempty"`
}

type Anchors struct {
	CapturedAt time.Time `json:"captured_utc"`
	Boot       Anchor    `json:"kernel_boot_estimate"`
	Logon      Anchor    `json:"interactive_logon"`
	Process    Anchor    `json:"process_created"`
}

type Event struct {
	Stage          string    `json:"stage"`
	Device         string    `json:"device,omitempty"`
	ObservedAt     time.Time `json:"observed_utc"`
	SinceProcessMS *int64    `json:"since_process_ms,omitempty"`
	SinceLogonMS   *int64    `json:"since_logon_ms,omitempty"`
	SinceBootMS    *int64    `json:"since_kernel_boot_estimate_ms,omitempty"`
	BeforeLogon    bool      `json:"observed_before_interactive_logon,omitempty"`
}

type Report struct {
	Anchors     Anchors      `json:"anchors"`
	Events      []Event      `json:"first_observations_this_process"`
	Attachments []Attachment `json:"observed_attachments,omitempty"`
	Scope       string       `json:"scope"`
}

type Tracker struct {
	sync.Mutex
	anchors     Anchors
	events      []Event
	attachments []Attachment
	presence    map[string]attachmentPresence
}

func copyAnchor(a Anchor) Anchor {
	if a.At != nil {
		at := *a.At
		a.At = &at
	}
	return a
}
func copyAnchors(a Anchors) Anchors {
	a.Boot = copyAnchor(a.Boot)
	a.Logon = copyAnchor(a.Logon)
	a.Process = copyAnchor(a.Process)
	return a
}
func copyDuration(v *int64) *int64 {
	if v == nil {
		return nil
	}
	n := *v
	return &n
}
func NewTracker(anchors Anchors) *Tracker { return &Tracker{anchors: copyAnchors(anchors)} }

// ObserveLogon changes measurement anchors only. The service's authenticated
// user-session binding supplies this anchor; it never grants device consent.
// Events observed before login remain at their original timestamps.
func (t *Tracker) ObserveLogon(anchor Anchor) bool {
	if !anchor.Available || anchor.At == nil || anchor.At.IsZero() {
		return false
	}
	t.Lock()
	defer t.Unlock()
	if t.anchors.Logon.Available && t.anchors.Logon.At != nil && t.anchors.Logon.At.Equal(*anchor.At) {
		return false
	}
	t.anchors.Logon = copyAnchor(anchor)
	for i := range t.events {
		t.events[i].SinceLogonMS = durationFrom(anchor, t.events[i].ObservedAt)
		t.events[i].BeforeLogon = t.events[i].ObservedAt.Before(*anchor.At)
	}
	return true
}

func durationFrom(a Anchor, at time.Time) *int64 {
	if !a.Available || a.At == nil || at.Before(*a.At) {
		return nil
	}
	ms := at.Sub(*a.At).Milliseconds()
	return &ms
}

// MarkFirst is bounded to the five fixed process/device stages. Repeated
// observations cannot replace the first one or create a new readiness proof.
func (t *Tracker) MarkFirst(stage, device string, at time.Time) bool {
	if !((stage == "shared_host_ready" && device == "") || ((stage == "device_present" || stage == "device_ready") && (device == "Mac" || device == "iPad"))) || at.IsZero() {
		return false
	}
	t.Lock()
	defer t.Unlock()
	for _, e := range t.events {
		if e.Stage == stage && e.Device == device {
			return false
		}
	}
	beforeLogon := t.anchors.Logon.Available && t.anchors.Logon.At != nil && at.Before(*t.anchors.Logon.At)
	t.events = append(t.events, Event{Stage: stage, Device: device, ObservedAt: at.UTC(), SinceProcessMS: durationFrom(t.anchors.Process, at), SinceLogonMS: durationFrom(t.anchors.Logon, at), SinceBootMS: durationFrom(t.anchors.Boot, at), BeforeLogon: beforeLogon})
	return true
}

func (t *Tracker) Snapshot() Report {
	t.Lock()
	defer t.Unlock()
	events := append([]Event(nil), t.events...)
	for i := range events {
		events[i].SinceProcessMS = copyDuration(events[i].SinceProcessMS)
		events[i].SinceLogonMS = copyDuration(events[i].SinceLogonMS)
		events[i].SinceBootMS = copyDuration(events[i].SinceBootMS)
	}
	return Report{Anchors: copyAnchors(t.anchors), Events: events, Attachments: copyAttachments(t.attachments), Scope: "READ_ONLY_OS_PRESENCE_AND_NETWORK_OBSERVATIONS_NOT_PHYSICAL_INSERTION_OR_STREAM_PROOF"}
}

var global struct {
	once    sync.Once
	tracker *Tracker
}

// Init is called once by the parent entry point, never from periodic UI refresh.
func Init() { global.once.Do(func() { global.tracker = NewTracker(captureNativeAnchors()) }) }
func RecordDevicePresent(device string) {
	Init()
	global.tracker.MarkFirst("device_present", device, time.Now())
}
func RecordSharedHostReady() { Init(); global.tracker.MarkFirst("shared_host_ready", "", time.Now()) }
func RecordDeviceReady(device string) {
	Init()
	global.tracker.MarkFirst("device_ready", device, time.Now())
}
func Snapshot() Report { Init(); return global.tracker.Snapshot() }
