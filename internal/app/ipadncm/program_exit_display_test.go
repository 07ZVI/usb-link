package ipadncm

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProgramExitDisplayPolling(t *testing.T) {
	for phase, want := range map[string]bool{"": false, "idle": false, "stopping_connections": true, "restoring": true, "ready": true, "failed": false, "committed": false} {
		if got := programExitPollingPhase(phase); got != want {
			t.Fatalf("%q: got %v", phase, got)
		}
	}
	if got := programExitDisplayPhase(json.RawMessage(`{"event":"status","program_exit":{"phase":"restoring","request_id":"x"}}`)); got != "restoring" {
		t.Fatal(got)
	}
	if programExitDisplayPhase(json.RawMessage(`not json`)) != "" || programExitDisplayPhase(json.RawMessage(`{}`)) != "" {
		t.Fatal("malformed or absent phase must read empty")
	}
	if uiPollDelay(true) >= time.Second || uiPollDelay(false) != time.Second {
		t.Fatal("exit polling must be faster than ordinary polling")
	}
}
