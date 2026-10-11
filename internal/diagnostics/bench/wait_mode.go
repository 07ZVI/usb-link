package bench

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event waits remain opt-in until the long real-host stability gate passes.
// Production keeps original polling.
var eventWaits atomic.Bool
var waitMode struct {
	sync.Mutex
	generation   uint64
	timer        *time.Timer
	listeners    map[uint64]func()
	nextListener uint64
	transitions  uint64
	diagnostics  func() any
}

func EventWaits() bool { return eventWaits.Load() }

// ReadEventWaitMode resets a native mode-change event and reads the mode under
// the same lock used to notify transitions. A transition cannot disappear
// between ResetEvent and entering a native wait. reset must not reenter bench.
func ReadEventWaitMode(reset func()) bool {
	waitMode.Lock()
	defer waitMode.Unlock()
	reset()
	return eventWaits.Load()
}

// ObserveEventWaitMode registers a native wake callback. wake must be quick and
// must not reenter bench. Unsubscribe joins any in-flight callback before the
// owner frees its native event; no background observer goroutine is needed.
func ObserveEventWaitMode(wake func()) func() {
	waitMode.Lock()
	waitMode.nextListener++
	id := waitMode.nextListener
	if waitMode.listeners == nil {
		waitMode.listeners = make(map[uint64]func())
	}
	waitMode.listeners[id] = wake
	waitMode.Unlock()
	return func() { waitMode.Lock(); delete(waitMode.listeners, id); waitMode.Unlock() }
}

func publishEventWaitMode(enabled bool) {
	eventWaits.Store(enabled)
	waitMode.transitions++
	for _, wake := range waitMode.listeners {
		wake()
	}
}
func SetEventWaitExperiment(seconds int) {
	duration := time.Duration(seconds) * time.Second
	if seconds <= 0 {
		duration = 0
	}
	setEventWaitDuration(duration)
}
func setEventWaitDuration(duration time.Duration) {
	waitMode.Lock()
	defer waitMode.Unlock()
	waitMode.generation++
	g := waitMode.generation
	if waitMode.timer != nil {
		waitMode.timer.Stop()
		waitMode.timer = nil
	}
	publishEventWaitMode(duration > 0)
	if duration > 0 {
		waitMode.timer = time.AfterFunc(duration, func() {
			waitMode.Lock()
			defer waitMode.Unlock()
			if waitMode.generation == g {
				publishEventWaitMode(false)
				waitMode.timer = nil
			}
		})
	}
}

// SetWaitDiagnostics installs a read-only atomic snapshot from the owned native
// waiters. Readers do not extend a lease or alter transport scheduling.
func SetWaitDiagnostics(snapshot func() any) {
	waitMode.Lock()
	waitMode.diagnostics = snapshot
	waitMode.Unlock()
}
func WaitDiagnostics() any {
	waitMode.Lock()
	defer waitMode.Unlock()
	result := map[string]any{"event_waits_enabled": eventWaits.Load(), "mode_transitions": waitMode.transitions, "read_only": true}
	if waitMode.diagnostics != nil {
		result["workers"] = waitMode.diagnostics()
	}
	return result
}
