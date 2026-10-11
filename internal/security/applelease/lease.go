// Package applelease implements a consented temporary service pause with
// restoration and a bounded watchdog. It never changes startup configuration.
package applelease

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	Stopped      uint32 = 1
	StartPending uint32 = 2
	StopPending  uint32 = 3
	Running      uint32 = 4
)

type Service interface {
	State() (uint32, error)
	Stop() error
	Start() error
}
type Report struct {
	Consent          bool   `json:"pause_and_conditional_mode_consent"`
	Before           uint32 `json:"service_state_before"`
	After            uint32 `json:"service_state_after"`
	StopAttempted    bool   `json:"stop_attempted"`
	StopConfirmed    bool   `json:"stop_confirmed"`
	RestoreAttempted bool   `json:"restore_attempted"`
	RestartAttempted bool   `json:"restart_attempted"`
	Restored         bool   `json:"restored_to_running"`
	Watchdog         bool   `json:"watchdog_restore"`
	Error            string `json:"error,omitempty"`
	RestoreError     string `json:"restore_error,omitempty"`
}
type Lease struct {
	s             Service
	mu            sync.Mutex
	r             Report
	once          sync.Once
	done          chan struct{}
	active        atomic.Bool
	watchdogAfter time.Duration
}

func New(s Service) *Lease {
	return &Lease{s: s, done: make(chan struct{}), watchdogAfter: 20 * time.Second}
}
func (l *Lease) update(f func(*Report)) { l.mu.Lock(); defer l.mu.Unlock(); f(&l.r) }
func (l *Lease) Report() Report         { l.mu.Lock(); defer l.mu.Unlock(); return l.r }
func (l *Lease) Active() bool           { return l.active.Load() }
func (l *Lease) Begin(consent bool) bool {
	l.update(func(r *Report) { r.Consent = consent })
	state, e := l.s.State()
	l.update(func(r *Report) { r.Before = state; r.After = state })
	if !consent {
		return false
	}
	if e != nil || state != Running {
		l.update(func(r *Report) { r.Error = "INITIAL_SERVICE_NOT_RUNNING" })
		return false
	}
	l.update(func(r *Report) { r.StopAttempted = true })
	if e = l.s.Stop(); e != nil {
		l.update(func(r *Report) { r.Error = "SERVICE_STOP_FAILED" })
		l.Close()
		return false
	}
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		state, e = l.s.State()
		if e != nil {
			break
		}
		if state == Stopped {
			l.update(func(r *Report) { r.StopConfirmed = true })
			l.active.Store(true)
			time.AfterFunc(l.watchdogAfter, func() {
				if l.active.CompareAndSwap(true, false) {
					l.update(func(r *Report) { r.Watchdog = true })
					l.Close()
				}
			})
			return true
		}
		if state != StopPending {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.update(func(r *Report) { r.Error = "SERVICE_STOP_NOT_CONFIRMED" })
	l.Close()
	return false
}
func (l *Lease) Close() {
	l.active.Store(false)
	l.once.Do(func() {
		defer close(l.done)
		r := l.Report()
		if !r.StopAttempted {
			return
		}
		l.update(func(r *Report) { r.RestoreAttempted = true })
		end := time.Now().Add(10 * time.Second)
		started := false
		for time.Now().Before(end) {
			state, e := l.s.State()
			l.update(func(r *Report) { r.After = state })
			if e != nil {
				l.update(func(r *Report) { r.RestoreError = "RESTORE_STATE_QUERY_FAILED" })
				return
			}
			if state == Running {
				l.update(func(r *Report) { r.Restored = true })
				return
			}
			if state == Stopped && !started {
				l.update(func(r *Report) { r.RestartAttempted = true })
				started = true
				if e = l.s.Start(); e != nil {
					l.update(func(r *Report) { r.RestoreError = "SERVICE_RESTART_FAILED" })
					return
				}
				continue
			}
			if state != StopPending && state != StartPending {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		l.update(func(r *Report) { r.RestoreError = "SERVICE_RESTORE_NOT_CONFIRMED" })
	})
	<-l.done
}
