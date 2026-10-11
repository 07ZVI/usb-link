package startuptelemetry

import "time"

type Attachment struct {
	Number               uint64     `json:"observation"`
	Device               string     `json:"device"`
	PresentAt            time.Time  `json:"first_unique_os_presence_utc"`
	ReadyAt              *time.Time `json:"first_observed_network_ready_utc,omitempty"`
	ElapsedMS            *int64     `json:"ms_from_first_os_presence_not_physical_insertion,omitempty"`
	AfterObservedAbsence bool       `json:"after_verified_os_absence"`
}
type attachmentPresence struct {
	present, absentSeen bool
	identity            string
	number              uint64
}

func (t *Tracker) ObservePresence(device, identity string, readable, absent bool, at time.Time) bool {
	if (device != "Mac" && device != "iPad") || !readable || at.IsZero() {
		return false
	}
	t.Lock()
	defer t.Unlock()
	if t.presence == nil {
		t.presence = map[string]attachmentPresence{}
	}
	p := t.presence[device]
	if absent {
		p.present = false
		p.identity = ""
		p.absentSeen = true
		t.presence[device] = p
		return false
	}
	if identity == "" || (p.present && p.identity == identity) {
		return false
	}
	p.number++
	t.attachments = append(t.attachments, Attachment{Number: p.number, Device: device, PresentAt: at.UTC(), AfterObservedAbsence: p.absentSeen})
	if len(t.attachments) > 16 {
		t.attachments = append([]Attachment(nil), t.attachments[len(t.attachments)-16:]...)
	}
	p.present, p.absentSeen, p.identity = true, false, identity
	t.presence[device] = p
	return true
}
func (t *Tracker) MarkAttachmentReady(device string, at time.Time) bool {
	t.Lock()
	defer t.Unlock()
	p := t.presence[device]
	if !p.present || at.IsZero() {
		return false
	}
	for i := len(t.attachments) - 1; i >= 0; i-- {
		a := &t.attachments[i]
		if a.Device != device || a.Number != p.number {
			continue
		}
		if a.ReadyAt != nil || at.Before(a.PresentAt) {
			return false
		}
		ready := at.UTC()
		ms := at.Sub(a.PresentAt).Milliseconds()
		a.ReadyAt = &ready
		a.ElapsedMS = &ms
		return true
	}
	return false
}
func copyAttachments(src []Attachment) []Attachment {
	r := append([]Attachment(nil), src...)
	for i := range r {
		r[i].ElapsedMS = copyDuration(r[i].ElapsedMS)
		if r[i].ReadyAt != nil {
			at := *r[i].ReadyAt
			r[i].ReadyAt = &at
		}
	}
	return r
}
func ObserveDevicePresence(device, identity string, readable, absent bool) bool {
	Init()
	return global.tracker.ObservePresence(device, identity, readable, absent, time.Now())
}
func RecordAttachmentReady(device string) bool {
	Init()
	return global.tracker.MarkAttachmentReady(device, time.Now())
}
func AttachmentAwaitingReady(device string) bool {
	Init()
	t := global.tracker
	t.Lock()
	defer t.Unlock()
	p := t.presence[device]
	if !p.present {
		return false
	}
	for i := len(t.attachments) - 1; i >= 0; i-- {
		a := t.attachments[i]
		if a.Device == device && a.Number == p.number {
			return a.ReadyAt == nil
		}
	}
	return false
}
