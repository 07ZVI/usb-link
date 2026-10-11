package ipadncm

import (
	"testing"
	"time"
)

func TestAMDSReplugRequiresFreshSameDeviceAfterReadableDetach(t *testing.T) {
	t0 := time.Now()
	root := `USB\VID_05AC&PID_12AB\ABC123456789`
	present := idlePresence{candidate: true, readable: true, identity: root}
	absent := idlePresence{absent: true, readable: true}
	var g amdsReplugGate
	if ready, _ := g.observe(t0, present, root); ready {
		t.Fatal("existing attachment accepted")
	}
	g.observe(t0, absent, root)
	g.observe(t0.Add(900*time.Millisecond), idlePresence{}, root)
	g.observe(t0.Add(2*time.Second), absent, root)
	if g.detached {
		t.Fatal("unreadable interval proved physical detach")
	}
	g.observe(t0.Add(3*time.Second), absent, root)
	if !g.detached {
		t.Fatal("readable detach not accepted")
	}
	if ready, changed := g.observe(t0.Add(4*time.Second), present, root); !ready || changed {
		t.Fatal("same device rejected")
	}
	present.identity = `USB\VID_05AC&PID_12AB\OTHER12345678`
	if ready, changed := g.observe(t0.Add(5*time.Second), present, root); ready || !changed {
		t.Fatal("replacement device accepted")
	}
}
