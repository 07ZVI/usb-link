package macconnection

import "time"

// Retry only service initialization. It never restarts USB or its adapter.
type serviceRetry struct {
	Failures int
	Next     time.Time
	Ready    bool
}

func (r *serviceRetry) due(now time.Time) bool { return !r.Ready && !now.Before(r.Next) }
func (r *serviceRetry) complete(now time.Time, err error) {
	if err == nil {
		r.Ready = true
		return
	}
	r.Failures++
	delay := time.Second * time.Duration(1<<min(r.Failures, 4))
	r.Next = now.Add(delay)
}
