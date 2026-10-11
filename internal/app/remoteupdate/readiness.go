package remoteupdate

import "time"

// Readiness never treats a monitoring process alone as a usable USB session.
type Readiness struct{ since time.Time }

func (r *Readiness) Observe(now time.Time, connected bool) bool {
	if !connected {
		r.since = time.Time{}
		return false
	}
	if r.since.IsZero() {
		r.since = now
	}
	return now.Sub(r.since) >= 30*time.Second
}
