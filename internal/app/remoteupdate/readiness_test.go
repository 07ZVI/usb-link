package remoteupdate

import (
	"testing"
	"time"
)

func TestReadinessRequiresContinuousUSBConnection(t *testing.T) {
	var r Readiness
	t0 := time.Unix(100, 0)
	if r.Observe(t0, false) || r.Observe(t0.Add(time.Minute), false) {
		t.Fatal("idle process acknowledged")
	}
	if r.Observe(t0, true) || r.Observe(t0.Add(29*time.Second), true) {
		t.Fatal("early readiness")
	}
	if r.Observe(t0.Add(30*time.Second), false) {
		t.Fatal("failure acknowledged")
	}
	if r.Observe(t0.Add(31*time.Second), true) || r.Observe(t0.Add(60*time.Second), true) {
		t.Fatal("failed session did not reset")
	}
	if !r.Observe(t0.Add(61*time.Second), true) {
		t.Fatal("stable connection not acknowledged")
	}
}
