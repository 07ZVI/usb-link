package ipadncm

import (
	"context"
	"time"
)

type modeArrivalCacheHint struct {
	readFailed, targetMatches bool
	hubErrors, portErrors     int
	devices                   int
	configuration             byte
}

func (h modeArrivalCacheHint) permitsFullRead() bool {
	return !h.readFailed && h.hubErrors == 0 && h.portErrors == 0 && h.devices == 1 && h.targetMatches && h.configuration == 5
}

// Notifications and cached readiness only schedule a complete target check.
// Neither can substitute for the identity and layout proof in observe.
func observeModeArrival(ctx context.Context, notifications <-chan struct{}, limit, fallback time.Duration, preflight, observe func() bool) {
	deadline := time.Now().Add(limit)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		ready := preflight == nil || preflight()
		if ready && ctx.Err() == nil && time.Now().Before(deadline) && observe() {
			return
		}
		timer := time.NewTimer(min(fallback, max(0, time.Until(deadline))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case _, open := <-notifications:
			timer.Stop()
			if !open {
				notifications = nil
			}
		case <-timer.C:
		}
	}
}
