package ipadncm

import "time"

func newAutomaticConnectionTimingController(stamp func(time.Time) (string, int64)) *connectionTimingController {
	c := &connectionTimingController{stamp: stamp}
	c.useAutomaticDetection()
	return c
}

// Ordinary detection needs no debug authority or preference I/O. Retire the
// old delayed selection while leaving the device and consent checks intact.
func (c *connectionTimingController) useAutomaticDetection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	c.selectionRevision++
	c.persistenceOperation++
	c.restoreAllowed = false
	if c.state.Mode != "fast" {
		_ = c.setLocked("fast", time.Now())
	}
	c.state.SavedMode = "fast"
	c.state.Persistence = "automatic"
	c.state.PersistenceError = ""
}
