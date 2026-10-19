package launcher

import (
	"strings"
	"sync"
	"time"

	"suhang/usbnet/internal/contracts/coreipc"
)

// The core service has no SCM recovery action by policy, so a core that
// stopped (listener failure, unexpected application stop, crash) stays stopped
// until something starts it. The login UI is that something: it starts the
// verified core again with bounded backoff, and never while the program is
// intentionally exiting, an installer owns the service, or the service is
// already starting or stopping on purpose.

type coreRecoveryAction int

const (
	coreRecoveryNone coreRecoveryAction = iota
	// The pipe or service is gone: start the verified core.
	coreRecoveryStart
	// The core is running but answers nothing for a long time: stop it
	// gracefully (it restores on stop) and start it again.
	coreRecoveryRestart
)

const (
	coreRecoveryDownCalls    = 2
	coreRecoveryHungAfter    = 90 * time.Second
	coreRecoveryFirstBackoff = 2 * time.Second
	coreRecoveryMaxBackoff   = 30 * time.Second
)

type coreRecovery struct {
	mu         sync.Mutex
	suppressed bool
	// blocked reports that someone else deliberately drives the service (an
	// installer transaction, a stop or start already in progress). Nil means
	// nothing blocks recovery.
	blocked func() bool
	running bool
	next    time.Time
	backoff time.Duration
}

// coreLinkKind separates a missing core from an unresponsive one. A reply from
// the core, even a refusal, is neither.
func coreLinkKind(err error) (down, unresponsive bool) {
	code, win32, _, transport := coreipc.ErrorDetail(err)
	if !transport {
		return false, false
	}
	switch {
	case code == "CORE_IPC_PIPE_ABSENT", strings.HasPrefix(code, "CORE_IPC_SERVER_REJECTED"):
		return true, false
	case strings.HasSuffix(code, "_TIMEOUT"), win32 == 109, win32 == 232, win32 == 233:
		return false, true
	}
	return false, false
}

func (r *coreRecovery) Suppress() {
	r.mu.Lock()
	r.suppressed = true
	r.mu.Unlock()
}

func (r *coreRecovery) Healthy() {
	r.mu.Lock()
	r.backoff = 0
	r.next = time.Time{}
	r.mu.Unlock()
}

// Decide is called after each failed call with the continuous outage so far.
// A returned action must be followed by Finish.
func (r *coreRecovery) Decide(now time.Time, err error, outage time.Duration, consecutive int) coreRecoveryAction {
	down, unresponsive := coreLinkKind(err)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.suppressed || r.running || now.Before(r.next) {
		return coreRecoveryNone
	}
	if r.blocked != nil && r.blocked() {
		return coreRecoveryNone
	}
	action := coreRecoveryNone
	switch {
	case down && consecutive >= coreRecoveryDownCalls:
		action = coreRecoveryStart
	case unresponsive && outage >= coreRecoveryHungAfter:
		action = coreRecoveryRestart
	}
	if action != coreRecoveryNone {
		r.running = true
	}
	return action
}

func (r *coreRecovery) Finish(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	switch {
	case r.backoff == 0:
		r.backoff = coreRecoveryFirstBackoff
	default:
		r.backoff = min(r.backoff*2, coreRecoveryMaxBackoff)
	}
	r.next = now.Add(r.backoff)
}
