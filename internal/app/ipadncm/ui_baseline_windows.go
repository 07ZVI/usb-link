//go:build windows && amd64

package ipadncm

import (
	"sync"
	"sync/atomic"
	"time"
)

var backgroundUIBaseline atomic.Bool
var backgroundUITimer struct {
	sync.Mutex
	timer      *time.Timer
	generation uint64
}

// Baseline replay is temporary, fixed-duration and only affects hidden UI work.
func MeasurementUIBaseline(seconds int) {
	backgroundUITimer.Lock()
	defer backgroundUITimer.Unlock()
	if backgroundUITimer.timer != nil {
		backgroundUITimer.timer.Stop()
	}
	backgroundUITimer.generation++
	generation := backgroundUITimer.generation
	backgroundUIBaseline.Store(seconds > 0)
	if seconds > 0 {
		backgroundUITimer.timer = time.AfterFunc(time.Duration(seconds)*time.Second, func() {
			backgroundUITimer.Lock()
			defer backgroundUITimer.Unlock()
			if generation == backgroundUITimer.generation {
				backgroundUIBaseline.Store(false)
				backgroundUITimer.timer = nil
			}
		})
	}
}
