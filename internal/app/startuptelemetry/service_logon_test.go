package startuptelemetry

import (
	"testing"
	"time"
)

func TestServiceReadinessBeforeOwnerLoginIsPreserved(t *testing.T) {
	boot := time.Unix(1000, 0).UTC()
	process := boot.Add(time.Second)
	tracker := NewTracker(Anchors{Process: Anchor{Available: true, At: &process}})
	ready := boot.Add(8 * time.Second)
	tracker.MarkFirst("device_ready", "Mac", ready)
	logon := boot.Add(20 * time.Second)
	if !tracker.ObserveLogon(Anchor{Available: true, At: &logon, Source: "owner"}) {
		t.Fatal("owner anchor not observed")
	}
	r := tracker.Snapshot()
	if !r.Events[0].BeforeLogon || r.Events[0].SinceLogonMS != nil || !r.Events[0].ObservedAt.Equal(ready) || *r.Events[0].SinceProcessMS != 7000 {
		t.Fatal("prelogin observation was hidden or rewritten")
	}
	if tracker.ObserveLogon(Anchor{}) || tracker.ObserveLogon(Anchor{Available: true, At: &logon}) {
		t.Fatal("missing/repeated anchor must not replace events")
	}
	later := logon.Add(2 * time.Second)
	tracker.MarkFirst("device_ready", "iPad", later)
	r = tracker.Snapshot()
	if r.Events[1].BeforeLogon || *r.Events[1].SinceLogonMS != 2000 {
		t.Fatal("postlogin duration incorrect")
	}
}
