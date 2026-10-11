package ipadncm

import (
	"context"
	"testing"
	"time"
)

func TestRecoveryTestStopsOnlyCurrentAttempt(t *testing.T) {
	var c RecoveryTestControl
	first, stop := context.WithCancel(context.Background())
	defer stop()
	detach := c.Attach(first, stop)
	defer detach()
	if e := c.Request(); e != nil {
		t.Fatal(e)
	}
	if c.Request() == nil {
		t.Fatal("duplicate accepted")
	}
	if first.Err() != nil {
		t.Fatal("cancelled before response grace period")
	}
	select {
	case <-first.Done():
	case <-time.After(time.Second):
		t.Fatal("attempt not stopped")
	}
	if !c.Consume() || c.Consume() {
		t.Fatal("request must be consumed once")
	}
}
func TestRecoveryTestCannotCancelReplacementOrAbsentAttempt(t *testing.T) {
	var c RecoveryTestControl
	if c.Request() == nil {
		t.Fatal("absent attempt accepted")
	}
	old, oldStop := context.WithCancel(context.Background())
	defer oldStop()
	detach := c.Attach(old, oldStop)
	if e := c.Request(); e != nil {
		t.Fatal(e)
	}
	detach()
	next, nextStop := context.WithCancel(context.Background())
	defer nextStop()
	defer c.Attach(next, nextStop)()
	time.Sleep(300 * time.Millisecond)
	if old.Err() != nil || next.Err() != nil {
		t.Fatal("stale request cancelled a detached or replacement attempt")
	}
	if !c.Consume() {
		t.Fatal("missing request")
	}
	nextStop()
	if c.Request() == nil {
		t.Fatal("cancelled attempt accepted")
	}
}
