package usbhost

import (
	"context"
	"errors"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"sync"
	"syscall"
	"time"
)

// Prepared resources are private until their entire permission/gateway setup
// succeeds. Cleanup must retain and resolve any durable ownership obligations.
type PreparedHost struct {
	// Admission calls this under the supervisor lock. Use only bounded native
	// readbacks: no supervisor callbacks, topology lock, PowerShell or trust UI.
	Healthy func() bool
	Cleanup func() error
}

type SupervisorSnapshot struct {
	State                string `json:"state"`
	Ready                bool   `json:"ready"`
	Generation           uint64 `json:"generation"`
	Attempts             uint64 `json:"attempts"`
	Failures             uint64 `json:"failures"`
	RetrySeconds         int    `json:"retry_seconds"`
	Sessions             int    `json:"sessions"`
	Problem              string `json:"problem,omitempty"`
	FailurePhase         string `json:"failure_phase,omitempty"`
	FailureCode          string `json:"failure_code,omitempty"`
	NativeError          uint32 `json:"native_error,omitempty"`
	NativeOperation      string `json:"native_operation,omitempty"`
	NativeHRESULT        uint32 `json:"native_hresult,omitempty"`
	FirstFailurePhase    string `json:"first_failure_phase,omitempty"`
	FirstFailureCode     string `json:"first_failure_code,omitempty"`
	FirstNativeError     uint32 `json:"first_native_error,omitempty"`
	FirstNativeOperation string `json:"first_native_operation,omitempty"`
	FirstNativeHRESULT   uint32 `json:"first_native_hresult,omitempty"`
}

type Supervisor struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	wake        chan struct{}
	changed     chan struct{}
	sessions    map[uint64]context.CancelFunc
	nextSession uint64
	snapshot    SupervisorSnapshot
	prepare     func(context.Context) (PreparedHost, error)
	healthy     func() bool
	// Tests drive real transitions with a controlled timer rather than waiting
	// minutes or bypassing preparation, ownership and cleanup behavior.
	after func(time.Duration) <-chan time.Time
}

func NewSupervisor(ctx context.Context, prepare func(context.Context) (PreparedHost, error)) *Supervisor {
	return newSupervisor(ctx, prepare, time.After)
}

func newSupervisor(ctx context.Context, prepare func(context.Context) (PreparedHost, error), after func(time.Duration) <-chan time.Time) *Supervisor {
	ctx, cancel := context.WithCancel(ctx)
	s := &Supervisor{ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1), changed: make(chan struct{}), sessions: map[uint64]context.CancelFunc{}, prepare: prepare, after: after, snapshot: SupervisorSnapshot{State: "preparing"}}
	go s.run()
	return s
}

func (s *Supervisor) signalLocked() { close(s.changed); s.changed = make(chan struct{}) }
func (s *Supervisor) Snapshot() SupervisorSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.snapshot
	v.Sessions = len(s.sessions)
	return v
}
func (s *Supervisor) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot.Ready && s.ctx.Err() == nil
}
func (s *Supervisor) Nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *Supervisor) Close() { s.cancel(); <-s.done }

func hostRetryDelay(failures uint64) time.Duration {
	if failures == 0 {
		return time.Second
	}
	if failures >= 6 {
		return 30 * time.Second
	}
	return time.Second << uint(failures-1)
}

// A lease is canceled before an unhealthy generation is cleaned/replaced.
// Its owner must finish its own USB cleanup before releasing the lease.
func (s *Supervisor) Acquire(ctx context.Context) (context.Context, func(), bool) {
	s.Nudge()
	for {
		s.mu.Lock()
		if ctx.Err() != nil || s.ctx.Err() != nil {
			s.mu.Unlock()
			return nil, nil, false
		}
		if s.snapshot.Ready && (s.healthy == nil || !s.healthy()) {
			// Fresh native admission proof under the same lock as lease
			// publication. Never spend a device retry on a stale ready snapshot.
			s.snapshot.Ready = false
			s.snapshot.State = "waiting"
			s.signalLocked()
			s.Nudge()
		}
		if s.snapshot.Ready {
			s.nextSession++
			id := s.nextSession
			child, cancel := context.WithCancel(ctx)
			s.sessions[id] = cancel
			s.signalLocked()
			s.mu.Unlock()
			var once sync.Once
			return child, func() {
				once.Do(func() { cancel(); s.mu.Lock(); delete(s.sessions, id); s.signalLocked(); s.mu.Unlock() })
			}, true
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, nil, false
		case <-s.ctx.Done():
			return nil, nil, false
		case <-changed:
		}
	}
}

func (s *Supervisor) drain() {
	s.mu.Lock()
	s.snapshot.Ready = false
	s.snapshot.State = "draining"
	s.healthy = nil
	for _, cancel := range s.sessions {
		cancel()
	}
	s.signalLocked()
	for len(s.sessions) > 0 {
		changed := s.changed
		s.mu.Unlock()
		<-changed
		s.mu.Lock()
	}
	s.mu.Unlock()
}

func (s *Supervisor) wait(delay time.Duration) bool {
	timer := s.after(delay)
	select {
	case <-s.ctx.Done():
		return false
	case <-s.wake:
		return s.ctx.Err() == nil
	case <-timer:
		return s.ctx.Err() == nil
	}
}

func (s *Supervisor) run() {
	defer close(s.done)
	var held PreparedHost
	failures := uint64(0)
	for {
		if s.ctx.Err() != nil {
			break
		}
		if held.Cleanup != nil {
			s.drain()
			if err := held.Cleanup(); err != nil {
				failures++
				s.fail("USB_HOST_CLEANUP_PENDING", "cleanup", err, failures)
				if !s.wait(hostRetryDelay(failures)) {
					break
				}
				continue
			}
			held = PreparedHost{}
		}
		s.mu.Lock()
		s.snapshot.State = "preparing"
		s.snapshot.RetrySeconds = 0
		s.snapshot.Attempts++
		s.signalLocked()
		s.mu.Unlock()
		prepared, err := s.prepare(s.ctx)
		held = prepared
		if s.ctx.Err() != nil {
			break
		}
		if err != nil || prepared.Cleanup == nil || prepared.Healthy == nil || !prepared.Healthy() {
			failures++
			s.fail("USB_HOST_PREPARATION_RETRYING", "preparation", err, failures)
			if !s.wait(hostRetryDelay(failures)) {
				break
			}
			continue
		}
		failures = 0
		s.mu.Lock()
		s.snapshot.Ready = true
		s.healthy = prepared.Healthy
		s.snapshot.State = "ready"
		s.snapshot.Generation++
		s.snapshot.Problem = ""
		s.snapshot.FailurePhase = ""
		s.snapshot.FailureCode = ""
		s.snapshot.NativeError = 0
		s.snapshot.NativeOperation = ""
		s.snapshot.NativeHRESULT = 0
		s.snapshot.FirstFailurePhase = ""
		s.snapshot.FirstFailureCode = ""
		s.snapshot.FirstNativeError = 0
		s.snapshot.FirstNativeOperation = ""
		s.snapshot.FirstNativeHRESULT = 0
		s.snapshot.RetrySeconds = 0
		s.signalLocked()
		s.mu.Unlock()
		for s.ctx.Err() == nil {
			if !s.wait(30 * time.Second) {
				break
			}
			if !s.Ready() || !prepared.Healthy() {
				s.drain()
				break
			}
		}
	}
	s.drain()
	// One bounded best-effort cleanup on exit; an error keeps its protected
	// journals for the next startup. Never erase evidence to report success.
	if held.Cleanup != nil {
		if err := held.Cleanup(); err != nil {
			s.fail("USB_HOST_EXIT_CLEANUP_PENDING", "exit_cleanup", err, 0)
		}
	}
	s.mu.Lock()
	s.snapshot.State = "stopped"
	s.snapshot.Ready = false
	s.signalLocked()
	s.mu.Unlock()
}

// Expose only the operation's fixed code or numeric OS error. Arbitrary error
// messages can contain paths, account names or other private runtime data.
func hostFailureDiagnostic(err error) (string, uint32) {
	if err == nil {
		return "USB_HOST_PREPARED_HEALTH_UNCONFIRMED", 0
	}
	if code := netconfig.HostPreparationFailureCode(err); code != "" {
		return code, 0
	}
	var native syscall.Errno
	if errors.As(err, &native) {
		return "USB_HOST_NATIVE_OPERATION_FAILED", uint32(native)
	}
	if operation, _ := netconfig.NativeStepFailureDetails(err); operation != "" {
		return "USB_HOST_NATIVE_STEP_FAILED", 0
	}
	code := err.Error()
	if strings.HasPrefix(code, "USB_HOST_") && len(code) <= 96 {
		valid := true
		for _, c := range code {
			if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
				valid = false
				break
			}
		}
		if valid {
			return code, 0
		}
	}
	return "USB_HOST_OPERATION_FAILED", 0
}

func (s *Supervisor) fail(code, phase string, cause error, failures uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.State = "waiting"
	s.snapshot.Ready = false
	s.snapshot.Problem = code
	s.snapshot.FailurePhase = phase
	s.snapshot.FailureCode, s.snapshot.NativeError = hostFailureDiagnostic(cause)
	s.snapshot.NativeOperation, s.snapshot.NativeHRESULT = netconfig.NativeStepFailureDetails(cause)
	// Keep the first actual failure until a complete preparation publishes Ready.
	// Later cleanup remains visible as current state, without erasing the cause.
	if s.snapshot.FirstFailureCode == "" {
		firstCode := s.snapshot.FailureCode
		if !netconfig.HostFailureCodeKnown(firstCode) {
			firstCode = "USB_HOST_OPERATION_FAILED"
		}
		firstPhase := phase
		switch firstPhase {
		case "preparation", "cleanup", "exit_cleanup", "health":
		default:
			firstPhase = "unavailable"
		}
		s.snapshot.FirstFailurePhase = firstPhase
		s.snapshot.FirstFailureCode = firstCode
		if firstCode == "USB_HOST_NATIVE_OPERATION_FAILED" {
			s.snapshot.FirstNativeError = s.snapshot.NativeError
		}
		s.snapshot.FirstNativeOperation = s.snapshot.NativeOperation
		s.snapshot.FirstNativeHRESULT = s.snapshot.NativeHRESULT
	}
	s.snapshot.Failures++
	s.snapshot.RetrySeconds = int(hostRetryDelay(failures) / time.Second)
	s.signalLocked()
}
