package ipadncm

import (
	"strings"
	"sync"
)

var displaySessions = struct {
	sync.Mutex
	states   map[string]*applicationState
	selected string
	manual   bool
}{}

func deviceMonitor(kind string) *applicationState {
	displaySessions.Lock()
	defer displaySessions.Unlock()
	return displaySessions.states[kind]
}

// Always publish both device slots; display selection must not hide a session.
func deviceDisplaySnapshots() []ApplicationResult {
	results := make([]ApplicationResult, 0, 2)
	for _, kind := range []string{"Mac", "iPad"} {
		r := ApplicationResult{DeviceKind: kind, Status: "MONITOR_WAITING", WindowsIPv4: "10.6.9.1", RemainingSeconds: -1}
		if s := deviceMonitor(kind); s != nil {
			r = s.snapshot()
			r.DeviceKind = kind
		}
		results = append(results, r)
	}
	return results
}
func selectedDeviceMonitor() *applicationState {
	displaySessions.Lock()
	defer displaySessions.Unlock()
	return displaySessions.states[displaySessions.selected]
}
func selectDevice(kind string) bool {
	displaySessions.Lock()
	defer displaySessions.Unlock()
	if displaySessions.states[kind] == nil {
		return false
	}
	displaySessions.selected, displaySessions.manual = kind, true
	return true
}
func sessionRunning(r ApplicationResult) bool {
	return r.Status == "MAC_RUNNING" || r.Status == "USB_APPLICATION_TRIAL_RUNNING"
}
func autoSelectSession(state *applicationState) {
	displaySessions.Lock()
	defer displaySessions.Unlock()
	if displaySessions.manual || !sessionRunning(state.snapshot()) {
		return
	}
	for kind, target := range displaySessions.states {
		if target == state {
			current := displaySessions.states[displaySessions.selected]
			if current == nil || !sessionRunning(current.snapshot()) {
				displaySessions.selected = kind
			}
			return
		}
	}
}
func deviceSummary() string {
	var parts []string
	for _, kind := range []string{"Mac", "iPad"} {
		if s := deviceMonitor(kind); s != nil {
			state := "等待連線"
			if sessionRunning(s.snapshot()) {
				state = "已連線"
			}
			parts = append(parts, kind+" · "+state)
		}
	}
	return strings.Join(parts, "    ")
}
