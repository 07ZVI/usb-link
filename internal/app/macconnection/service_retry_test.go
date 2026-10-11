package macconnection

import (
	"errors"
	"testing"
	"time"
)

func TestServiceRetryRecoversWithoutBusyLoop(t *testing.T) {
	now := time.Unix(100, 0)
	r := serviceRetry{}
	for i := 0; i < 8; i++ {
		if !r.due(now) {
			t.Fatal("retry never becomes eligible")
		}
		r.complete(now, errors.New("temporary listener failure"))
		if r.due(now) || r.due(r.Next.Add(-time.Nanosecond)) {
			t.Fatal("busy retry")
		}
		if r.Next.Sub(now) > 16*time.Second {
			t.Fatal("unbounded backoff")
		}
		now = r.Next
	}
	r.complete(now, nil)
	if r.due(now.Add(time.Hour)) {
		t.Fatal("successful listener restarted")
	}
}
