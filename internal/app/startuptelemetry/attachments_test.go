package startuptelemetry

import (
	"testing"
	"time"
)

func TestAttachmentObservationsRequireReadableUniquePresenceAndKeepEachReplug(t *testing.T) {
	x := NewTracker(Anchors{})
	start := time.Unix(100, 0)
	if x.ObservePresence("iPad", "root", false, false, start) || x.MarkAttachmentReady("iPad", start) {
		t.Fatal("unknown presence counted")
	}
	for i := 0; i < 3; i++ {
		at := start.Add(time.Duration(i) * time.Minute)
		x.ObservePresence("iPad", "", true, true, at)
		if !x.ObservePresence("iPad", "root", true, false, at.Add(time.Second)) {
			t.Fatal("replug omitted")
		}
		if x.ObservePresence("iPad", "root", true, false, at.Add(2*time.Second)) {
			t.Fatal("duplicate start")
		}
		if !x.MarkAttachmentReady("iPad", at.Add(4*time.Second)) || x.MarkAttachmentReady("iPad", at.Add(5*time.Second)) {
			t.Fatal("ready replaced")
		}
	}
	r := x.Snapshot()
	if len(r.Attachments) != 3 {
		t.Fatal(r)
	}
	for _, a := range r.Attachments {
		if !a.AfterObservedAbsence || a.ElapsedMS == nil || *a.ElapsedMS != 3000 {
			t.Fatal(a)
		}
	}
	*r.Attachments[0].ElapsedMS = 99
	if *x.Snapshot().Attachments[0].ElapsedMS != 3000 {
		t.Fatal("snapshot aliases tracker")
	}
}
