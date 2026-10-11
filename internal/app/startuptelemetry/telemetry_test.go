package startuptelemetry

import (
	"testing"
	"time"
)

func TestMissingLoginAnchorNeverBecomesProcessStart(t *testing.T) {
	start := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	tr := NewTracker(Anchors{Process: Anchor{Available: true, At: &start, Source: "GET_PROCESS_TIMES_CREATION"}, Logon: Anchor{Problem: "INTERACTIVE_LOGON_UNAVAILABLE"}})
	if !tr.MarkFirst("device_present", "iPad", start.Add(2*time.Second)) || !tr.MarkFirst("shared_host_ready", "", start.Add(5*time.Second)) {
		t.Fatal("first events rejected")
	}
	if tr.MarkFirst("device_present", "iPad", start.Add(20*time.Second)) || tr.MarkFirst("device_ready", "raw serial", start.Add(time.Minute)) {
		t.Fatal("accepted duplicate/arbitrary input")
	}
	r := tr.Snapshot()
	if r.Anchors.Logon.Available || r.Anchors.Logon.At != nil || len(r.Events) != 2 || r.Events[0].SinceLogonMS != nil || r.Events[0].SinceProcessMS == nil || *r.Events[0].SinceProcessMS != 2000 {
		t.Fatal("login synthesized or duration incorrect")
	}
}

func TestTimingStagesStayDistinctAndClockRollbackUnavailable(t *testing.T) {
	boot := time.Unix(1700000000, 0)
	login := boot.Add(time.Minute)
	process := login.Add(10 * time.Second)
	tr := NewTracker(Anchors{Boot: Anchor{Available: true, At: &boot}, Logon: Anchor{Available: true, At: &login}, Process: Anchor{Available: true, At: &process}})
	for _, v := range []struct{ stage, device string }{{"device_present", "Mac"}, {"device_present", "iPad"}, {"shared_host_ready", ""}, {"device_ready", "Mac"}, {"device_ready", "iPad"}} {
		if !tr.MarkFirst(v.stage, v.device, process.Add(time.Second)) {
			t.Fatal("valid stage rejected")
		}
	}
	r := tr.Snapshot()
	if len(r.Events) != 5 || *r.Events[0].SinceBootMS != 71000 || *r.Events[0].SinceLogonMS != 11000 || *r.Events[0].SinceProcessMS != 1000 {
		t.Fatal("anchors conflated")
	}
	if durationFrom(Anchor{Available: true, At: &process}, boot) != nil {
		t.Fatal("negative interval represented as elapsed")
	}
}

func TestFiletimeAnchorRejectsUnavailableAndFuture(t *testing.T) {
	now := time.Date(2026, 10, 9, 1, 0, 0, 0, time.UTC)
	const epoch uint64 = 116444736000000000
	good := epoch + uint64(now.Unix())*10000000
	if at, ok := filetimeAnchor(good, now); !ok || !at.Equal(now) {
		t.Fatal("valid Windows timestamp rejected")
	}
	for _, ticks := range []uint64{0, epoch - 1, good + uint64(10*time.Second/100), ^uint64(0)} {
		if _, ok := filetimeAnchor(ticks, now); ok {
			t.Fatal("bad native timestamp accepted")
		}
	}
}
