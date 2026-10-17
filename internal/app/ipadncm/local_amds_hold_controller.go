package ipadncm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type localAMDSHoldBackend interface {
	recover() error
	start(func() bool) error
	stop() error
	sample() (localAMDSHoldSample, error)
}
type localAMDSHoldController struct {
	runtimeAllowed     func() bool
	mu                 sync.Mutex
	operation          sync.Mutex
	preference         sync.Mutex
	state              localAMDSHoldStatus
	master             bool
	revision           uint64
	preferenceRevision uint64
	attempted          uint64
	attemptValid       bool
	recovered          bool
	running            bool
	ctx                context.Context
	backend            localAMDSHoldBackend
	save               func(bool) error
	read               func() (bool, error)
	stamp              func() (string, string, int64)
	wake               chan struct{}
}

func newLocalAMDSHoldController() *localAMDSHoldController {
	return &localAMDSHoldController{wake: make(chan struct{}, 1), state: localAMDSHoldStatus{Available: true, Phase: "starting", Persistence: "unknown", SampledMS: -1}}
}
func (c *localAMDSHoldController) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *localAMDSHoldController) snapshot() localAMDSHoldStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state

	return s
}
func (c *localAMDSHoldController) configure(save func(bool) error, read func() (bool, error)) {
	c.mu.Lock()
	c.save, c.read = save, read
	c.mu.Unlock()
}
func (c *localAMDSHoldController) masterChanged(on bool) {
	c.mu.Lock()
	c.master = on
	c.revision++
	rev := c.revision
	c.state.Requested = false
	c.state.Effective = false
	if on {
		c.preferenceRevision = rev
		c.state.Persistence = "loading"
		c.state.Busy = true
	} else {
		c.state.Phase = "stopping"
	}
	read := c.read
	c.mu.Unlock()
	c.signal()
	if on {
		go c.persist(rev, true, false, nil, read)
	}
}
func (c *localAMDSHoldController) set(on bool, id string) error {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdefABCDEF") != "" {
		return errors.New("AMDS_HOLD_REQUEST_INVALID")
	}
	c.mu.Lock()
	if on && !c.master {
		c.state.RejectedID = id
		c.state.RejectedError = "AMDS_HOLD_DEBUG_REQUIRED"
		c.mu.Unlock()
		return errors.New("AMDS_HOLD_DEBUG_REQUIRED")
	}
	c.revision++
	rev := c.revision
	c.preferenceRevision = rev
	c.state.RequestID = id
	c.state.RejectedID = ""
	c.state.RejectedError = ""
	c.state.Requested = on
	c.state.Effective = false
	c.state.Busy = true
	c.state.Persistence = "saving"
	c.state.Error = ""
	c.state.CauseCode = ""
	c.state.NativeCode = 0
	c.state.Identity = nil
	if !on {
		c.state.Phase = "stopping"
	}
	save := c.save
	c.mu.Unlock()
	c.signal()
	go c.persist(rev, false, on, save, nil)
	return nil
}
func (c *localAMDSHoldController) persist(rev uint64, restore, on bool, save func(bool) error, read func() (bool, error)) {
	c.preference.Lock()
	defer c.preference.Unlock()
	c.mu.Lock()
	current := c.preferenceRevision == rev
	c.mu.Unlock()
	if !current {
		return
	}
	var err error
	if restore {
		if read == nil {
			err = errors.New("unavailable")
		} else {
			on, err = read()
		}
	} else {
		if save == nil {
			err = errors.New("unavailable")
		} else {
			err = save(on)
		}
	}
	c.mu.Lock()
	if err == nil {
		c.state.SavedEnabled = on
	}
	if c.preferenceRevision == rev {
		c.state.Busy = false
		if err != nil {
			c.state.Persistence = "failed"
			c.state.Error = "AMDS_HOLD_PREFERENCE_FAILED"
		} else {
			c.state.Persistence = "saved"
			if c.revision == rev {
				c.state.Requested = on && c.master
			}
			c.state.Error = ""
		}
	}
	c.mu.Unlock()
	c.signal()
}
func (c *localAMDSHoldController) allowed(rev uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return (c.runtimeAllowed == nil || c.runtimeAllowed()) && c.revision == rev && c.master && c.state.Requested && c.state.Persistence == "saved" && (c.ctx == nil || c.ctx.Err() == nil)
}

func (c *localAMDSHoldController) selected(rev uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.revision == rev && c.master && c.state.Requested && c.state.Persistence == "saved" && (c.ctx == nil || c.ctx.Err() == nil)
}
func (c *localAMDSHoldController) publish(phase string, effective bool, err error) {
	utc, run, ms := "", "", int64(-1)
	if c.stamp != nil {
		utc, run, ms = c.stamp()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.SampledUTC, c.state.RunID, c.state.SampledMS = utc, run, ms
	c.state.Phase = phase
	if phase == "starting" {
		c.state.Identity = nil
	}
	c.state.Restored = phase == "off" && err == nil
	if c.state.Restored && c.state.OriginalState != 0 {
		c.state.ServiceState = c.state.OriginalState
	}
	c.state.Effective = effective && c.master && c.state.Requested && c.state.Persistence == "saved" && (c.ctx == nil || c.ctx.Err() == nil)
	c.state.CauseCode = ""
	c.state.NativeCode = 0
	if err != nil {
		c.state.Error = "AMDS_HOLD_OPERATION_FAILED"
		var failure *localAMDSHoldFailure
		if errors.As(err, &failure) {
			c.state.CauseCode = failure.Code
			c.state.NativeCode = failure.Native
			if failure.Identity != nil {
				identity := *failure.Identity
				c.state.Identity = &identity
			}
		}
	} else if c.state.Persistence != "failed" {
		c.state.Error = ""
	}
}
func (c *localAMDSHoldController) step() {
	c.operation.Lock()
	defer c.operation.Unlock()
	if c.backend == nil {
		return
	}
	if c.awaitingSessionCleanup() {
		return
	}
	if !c.recovered {
		if e := c.backend.recover(); e != nil {
			c.publish("recovery_pending", false, e)
			return
		}
		c.recovered = true
		c.running = false
	}
	c.mu.Lock()
	rev := c.revision
	c.mu.Unlock()
	on := c.selected(rev)
	if c.running && !on {
		if e := c.backend.stop(); e != nil {
			c.publish("recovery_pending", false, e)
			return
		}
		c.running = false
	}
	if !on {
		c.publish("off", false, nil)
		return
	}
	if !c.running {
		if c.attemptValid && c.attempted == rev {
			return
		}
		c.attemptValid = true
		c.attempted = rev
		c.publish("starting", false, nil)
		if e := c.backend.start(func() bool { return c.allowed(rev) }); e != nil {
			if c.awaitingSessionCleanup() {
				return
			}
			if stopErr := c.backend.stop(); stopErr != nil {
				c.recovered = false
				c.publish("recovery_pending", false, stopErr)
			} else {
				c.publish("failed", false, e)
			}
			return
		}
		c.running = true
		if !c.allowed(rev) {
			if c.awaitingSessionCleanup() {
				return
			}
			if e := c.backend.stop(); e != nil {
				c.recovered = false
				c.publish("recovery_pending", false, e)
			} else {
				c.running = false
				c.publish("off", false, nil)
			}
			return
		}
	}
	sample, e := c.backend.sample()
	if e != nil {
		if c.awaitingSessionCleanup() {
			return
		}
		if stopErr := c.backend.stop(); stopErr != nil {
			c.recovered = false
			c.publish("recovery_pending", false, stopErr)
		} else {
			c.running = false
			c.publish("failed", false, e)
		}
		return
	}
	c.mu.Lock()
	c.state.localAMDSHoldSample = sample
	c.mu.Unlock()
	c.publish("held", true, nil)
}
func (c *localAMDSHoldController) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		c.step()
		select {
		case <-ctx.Done():
			c.masterChanged(false)
			c.operation.Lock()
			e := c.backend.stop()
			c.operation.Unlock()
			if e != nil {
				c.publish("recovery_pending", false, e)
			} else {
				c.publish("off", false, nil)
			}
			return
		case <-c.wake:
		case <-tick.C:
		}
	}
}
