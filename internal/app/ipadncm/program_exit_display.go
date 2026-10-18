package ipadncm

import (
	"encoding/json"
	"time"
)

// The renderer window is hidden as soon as exit is requested, so the login
// process observes the core's phases closely instead of once per second. This
// only changes how soon the already-published phase is read; it grants nothing.
const (
	uiPollInterval     = time.Second
	uiExitPollInterval = 200 * time.Millisecond
	exitRequestGrace   = 30 * time.Second
)

// programExitDisplayPhase extracts the program-exit phase from a display
// status; "" when absent or malformed.
func programExitDisplayPhase(desktop json.RawMessage) string {
	var status struct {
		Exit struct {
			Phase string `json:"phase"`
		} `json:"program_exit"`
	}
	if json.Unmarshal(desktop, &status) != nil {
		return ""
	}
	return status.Exit.Phase
}

// Exit work is in flight (or just finished) for these phases.
func programExitPollingPhase(phase string) bool {
	switch phase {
	case "stopping_connections", "restoring", "ready":
		return true
	}
	return false
}

func uiPollDelay(exiting bool) time.Duration {
	if exiting {
		return uiExitPollInterval
	}
	return uiPollInterval
}
