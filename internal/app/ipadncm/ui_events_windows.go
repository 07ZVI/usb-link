//go:build windows && amd64

package ipadncm

import (
	"sync"
	"time"
)

type uiEvent struct {
	UTC    string `json:"utc"`
	Reason string `json:"reason"`
	Action string `json:"action"`
	PID    int    `json:"pid,omitempty"`
}

var uiHistory struct {
	sync.Mutex
	events []uiEvent
	total  uint64
}

func recordUIEvent(reason, action string, pid int) {
	uiHistory.Lock()
	defer uiHistory.Unlock()
	uiHistory.total++
	if len(uiHistory.events) == 128 {
		copy(uiHistory.events, uiHistory.events[1:])
		uiHistory.events = uiHistory.events[:127]
	}
	uiHistory.events = append(uiHistory.events, uiEvent{time.Now().UTC().Format(time.RFC3339Nano), reason, action, pid})
}
func UIEvents() any {
	uiHistory.Lock()
	defer uiHistory.Unlock()
	return struct {
		Total  uint64    `json:"total"`
		Events []uiEvent `json:"events"`
	}{uiHistory.total, append([]uiEvent(nil), uiHistory.events...)}
}
