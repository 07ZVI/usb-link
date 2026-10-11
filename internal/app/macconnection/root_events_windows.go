//go:build windows && amd64

package macconnection

import (
	"suhang/usbnet/internal/security/deviceguard"
	"sync"
	"sync/atomic"
	"time"
)

var rootOnce sync.Once
var observedRoot rootObservation
var rootPolling atomic.Bool
var rootPreset struct {
	sync.Mutex
	generation uint64
	timer      *time.Timer
}

// One process-lifetime subscription; CM invalidates before the next caller's
// inventory read. Enrollment still performs currentPair directly.
func currentObservedRoot() string {
	rootOnce.Do(func() {
		events, _, e := deviceguard.SubscribeChanges()
		if e == nil {
			observedRoot.events = events
		}
	})
	return observedRoot.current(func() (string, error) { r, _, e := currentPair(); return r, e }, rootPolling.Load())
}
func SetRootPollingBaseline(seconds int) {
	rootPreset.Lock()
	defer rootPreset.Unlock()
	rootPreset.generation++
	g := rootPreset.generation
	if rootPreset.timer != nil {
		rootPreset.timer.Stop()
	}
	rootPolling.Store(seconds > 0)
	observedRoot.Lock()
	observedRoot.valid = false
	observedRoot.Unlock()
	if seconds > 0 {
		rootPreset.timer = time.AfterFunc(time.Duration(seconds)*time.Second, func() {
			rootPreset.Lock()
			defer rootPreset.Unlock()
			if rootPreset.generation == g {
				rootPolling.Store(false)
				observedRoot.Lock()
				observedRoot.valid = false
				observedRoot.Unlock()
				rootPreset.timer = nil
			}
		})
	}
}
