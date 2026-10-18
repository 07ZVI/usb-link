//go:build windows && amd64

package ipadncm

import "time"

// A request in flight can still be answered by a snapshot that predates it;
// the grace period bounds how long that stale "idle" may be ignored.

func (u *modernUI) noteExitRequested() {
	u.exitUntil.Store(time.Now().Add(exitRequestGrace).UnixNano())
	setTrayExitState(true)
}
func (u *modernUI) clearExitRequested() {
	u.exitUntil.Store(0)
	setTrayExitState(false)
}
func (u *modernUI) exiting() bool { return time.Now().UnixNano() < u.exitUntil.Load() }

// A phase the core reports overrides the grace period either way.
func (u *modernUI) observeExitPhase(phase string) {
	switch {
	case programExitPollingPhase(phase):
		u.exitUntil.Store(time.Now().Add(exitRequestGrace).UnixNano())
		setTrayExitState(true)
	case phase != "" && phase != "idle":
		u.clearExitRequested() // failed or committed
	default:
		setTrayExitState(u.exiting())
	}
}
