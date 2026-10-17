package ipadncm

import (
	"errors"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"sync"
	"sync/atomic"
)

var localPhotoStrategyMutex sync.Mutex

func WithLocalPhotoStrategySelection(f func() error) error {
	localPhotoStrategyMutex.Lock()
	defer localPhotoStrategyMutex.Unlock()
	return f()
}

type defaultNetworkIsolationStatus struct {
	Phase          string `json:"phase"`
	Busy           bool   `json:"busy"`
	Restored       bool   `json:"restored"`
	Error          string `json:"error,omitempty"`
	PhotoRestored  bool   `json:"photo_restored"`
	AMDSRestored   bool   `json:"amds_restored"`
	PolicyRestored bool   `json:"policy_restored"`
	PhotoEffective bool   `json:"photo_effective"`
	AMDSEffective  bool   `json:"amds_effective"`
}

// One serialized lifecycle owns activation and recovery. Diagnostics use a
// separate mutex so the UI can show progress during native restoration.
type defaultIsolationLifecycle struct {
	operation           sync.Mutex
	mu                  sync.Mutex
	state               defaultNetworkIsolationStatus
	policy, photo, amds func() error
	activate            func()
	quiesce             func()
	started, stopped    bool
	revoked             atomic.Bool
}

func (c *defaultIsolationLifecycle) snapshot() defaultNetworkIsolationStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *defaultIsolationLifecycle) restore() error {
	// Attempt every independent recovery even if one fails. Unknown receipts
	// remain owned by their original recovery code, never deleted here.
	p, a, f := c.policy(), c.amds(), c.photo()
	c.mu.Lock()
	c.state.PolicyRestored, c.state.AMDSRestored, c.state.PhotoRestored = p == nil, a == nil, f == nil
	c.state.Restored = p == nil && a == nil && f == nil
	c.state.Error = ""
	if !c.state.Restored {
		c.state.Error = "NETWORK_ISOLATION_RESTORE_PENDING"
	}
	c.mu.Unlock()
	if p != nil || a != nil || f != nil {
		return errors.New("NETWORK_ISOLATION_RESTORE_PENDING")
	}
	return nil
}

func (c *defaultIsolationLifecycle) start() error {
	c.operation.Lock()
	defer c.operation.Unlock()
	if c.started || c.stopped {
		return errors.New("NETWORK_ISOLATION_ALREADY_STARTED_OR_STOPPED")
	}
	c.started = true
	c.mu.Lock()
	c.state = defaultNetworkIsolationStatus{Phase: "recovering_previous", Busy: true}
	c.mu.Unlock()
	err := c.restore()
	if err == nil && c.revoked.Load() {
		err = errors.New("NETWORK_ISOLATION_CANCELLED")
	}
	if err == nil {
		c.activate()
	}
	c.mu.Lock()
	c.state.Busy = false
	if err != nil {
		c.state.Phase = "recovery_pending"
	} else {
		c.state.Phase = "running"
		c.state.Restored, c.state.PhotoRestored, c.state.AMDSRestored = false, false, false
	}
	c.mu.Unlock()
	return err
}

func (c *defaultIsolationLifecycle) stop() error {
	defer shutdowntrace.Begin(shutdowntrace.PhaseDefaultIsolationStop)()
	c.revoked.Store(true)
	c.operation.Lock()
	defer c.operation.Unlock()
	c.mu.Lock()
	c.state.Phase, c.state.Busy = "restoring", true
	c.state.Restored = false
	c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		c.quiesce()
	}
	err := c.restore()
	c.mu.Lock()
	c.state.Busy = false
	if err == nil {
		c.state.Phase = "restored"
	} else {
		c.state.Phase = "recovery_pending"
	}
	c.mu.Unlock()
	return err
}

func (c *localPhotoController) runtimeDefault(on bool) {
	c.mu.Lock()
	c.master, c.state.Requested = on, on
	c.revision++
	c.state.Persistence, c.state.Busy, c.state.SavedEnabled = "saved", false, false
	if !on {
		c.state.Effective = false
	}
	c.mu.Unlock()
	c.signal()
}

func (c *localAMDSHoldController) runtimeDefault(on bool) {
	c.mu.Lock()
	c.master, c.state.Requested = on, on
	c.revision++
	c.state.Persistence, c.state.Busy, c.state.SavedEnabled = "saved", false, false
	if !on {
		c.state.Effective = false
	}
	c.mu.Unlock()
	c.signal()
}

// Application cancellation revokes new mutations immediately. Restoring an
// existing lease waits for explicit Stop after the network owner has joined.
func (c *localPhotoController) awaitingSessionCleanup() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtimeAllowed != nil && !c.runtimeAllowed() && c.master && c.state.Requested && (c.context == nil || c.context.Err() == nil)
}

func (c *localAMDSHoldController) awaitingSessionCleanup() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtimeAllowed != nil && !c.runtimeAllowed() && c.master && c.state.Requested && (c.ctx == nil || c.ctx.Err() == nil)
}
