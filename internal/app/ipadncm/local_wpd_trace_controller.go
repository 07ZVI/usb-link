//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type localWPDTraceBackend interface {
	recover() error
	start(func() bool) error
	stop() error
	sample() (localWPDTraceSample, error)
}
type localWPDTraceController struct {
	mu                 sync.Mutex
	operation          sync.Mutex
	preference         sync.Mutex
	state              localWPDTraceStatus
	master             bool
	automatic          bool
	revision           uint64
	preferenceRevision uint64
	attempted          uint64
	attemptValid       bool
	recovered          bool
	running            bool
	ctx                context.Context
	backend            localWPDTraceBackend
	save               func(bool) error
	read               func() (bool, error)
	stamp              func() (string, string, int64)
	wake               chan struct{}
}

func newLocalWPDTraceController() *localWPDTraceController {
	return &localWPDTraceController{wake: make(chan struct{}, 1), state: localWPDTraceStatus{Available: true, Phase: "starting", Persistence: "unknown", Scope: "system_wpd_unattributed", TraceLimitMiB: 0, SampledMS: -1, localWPDTraceSample: newWPDTraceProviderSample()}}
}

func newAutomaticLocalWPDTraceController() *localWPDTraceController {
	c := newLocalWPDTraceController()
	c.automatic = true
	return c
}

func (c *localWPDTraceController) captureProviderResult() {
	if b, ok := c.backend.(interface{ cachedSample() localWPDTraceSample }); ok {
		s := b.cachedSample()
		c.mu.Lock()
		c.state.localWPDTraceSample = s
		c.mu.Unlock()
	}
}
func (c *localWPDTraceController) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *localWPDTraceController) snapshot() localWPDTraceStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	if s.Ownership != nil {
		v := *s.Ownership
		s.Ownership = &v
	}
	s.Recent = append([]localWPDTraceEvent(nil), s.Recent...)
	return s
}
func (c *localWPDTraceController) configure(save func(bool) error, read func() (bool, error)) {
	c.mu.Lock()
	c.save, c.read = save, read
	c.mu.Unlock()
}
func (c *localWPDTraceController) masterChanged(on bool) {
	c.mu.Lock()
	c.master = on
	c.revision++
	rev := c.revision
	if c.automatic {
		// Invalidate obsolete preference work before publishing the master intent.
		// The worker still verifies ownership and confirms native start/stop.
		c.preferenceRevision = rev
		c.state.Requested = on
		c.state.Effective = false
		c.state.SavedEnabled = false
		c.state.Persistence = "automatic"
		c.state.Busy = false
		if on {
			c.state.Phase = "starting"
		} else {
			c.state.Phase = "stopping"
		}
		c.mu.Unlock()
		c.signal()
		return
	}
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
func (c *localWPDTraceController) set(on bool, id string) error {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdefABCDEF") != "" {
		return errors.New("WPD_TRACE_REQUEST_INVALID")
	}
	c.mu.Lock()
	if c.automatic {
		c.state.RejectedID, c.state.RejectedError = id, "WPD_TRACE_FOLLOWS_DEBUG_MASTER"
		c.mu.Unlock()
		return errors.New("WPD_TRACE_FOLLOWS_DEBUG_MASTER")
	}
	if on && !c.master {
		c.state.RejectedID = id
		c.state.RejectedError = "WPD_TRACE_DEBUG_REQUIRED"
		c.mu.Unlock()
		return errors.New("WPD_TRACE_DEBUG_REQUIRED")
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
	c.state.Ownership = nil
	if !on {
		c.state.Phase = "stopping"
	}
	save := c.save
	c.mu.Unlock()
	c.signal()
	go c.persist(rev, false, on, save, nil)
	return nil
}
func (c *localWPDTraceController) persist(rev uint64, restore, on bool, save func(bool) error, read func() (bool, error)) {
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
			c.state.Error = "WPD_TRACE_PREFERENCE_FAILED"
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
func (c *localWPDTraceController) allowed(rev uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.revision == rev && c.master && c.state.Requested && c.persistenceReadyLocked() && (c.ctx == nil || c.ctx.Err() == nil)
}

func (c *localWPDTraceController) persistenceReadyLocked() bool {
	return c.automatic && c.state.Persistence == "automatic" || !c.automatic && c.state.Persistence == "saved"
}
func (c *localWPDTraceController) publish(phase string, effective bool, err error) {
	utc, run, ms := "", "", int64(-1)
	if c.stamp != nil {
		utc, run, ms = c.stamp()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.SampledUTC, c.state.RunID, c.state.SampledMS = utc, run, ms
	c.state.Phase = phase
	c.state.Effective = effective && c.master && c.state.Requested && c.persistenceReadyLocked() && (c.ctx == nil || c.ctx.Err() == nil)
	c.state.CauseCode = ""
	c.state.NativeCode = 0
	c.state.Ownership = nil
	if err != nil {
		c.state.Error = "WPD_TRACE_OPERATION_FAILED"
		var failure *localWPDTraceFailure
		if errors.As(err, &failure) {
			c.state.CauseCode = failure.Code
			c.state.NativeCode = failure.Native
			if failure.Ownership != nil {
				v := *failure.Ownership
				c.state.Ownership = &v
			}
		}
	} else if c.state.Persistence != "failed" {
		c.state.Error = ""
	}
}
func (c *localWPDTraceController) step() {
	c.operation.Lock()
	defer c.operation.Unlock()
	if c.backend == nil {
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
	on := c.allowed(rev)
	if c.running && !on {
		if e := c.stopBackend(); e != nil {
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
			c.captureProviderResult()
			if stopErr := c.stopBackend(); stopErr != nil {
				c.recovered = false
				c.publish("recovery_pending", false, stopErr)
			} else {
				c.publish("failed", false, e)
			}
			return
		}
		c.running = true
		c.captureProviderResult()
		if !c.allowed(rev) {
			if e := c.stopBackend(); e != nil {
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
		c.captureProviderResult()
		if stopErr := c.stopBackend(); stopErr != nil {
			c.recovered = false
			c.publish("recovery_pending", false, stopErr)
		} else {
			c.running = false
			c.publish("failed", false, e)
		}
		return
	}
	c.mu.Lock()
	c.state.localWPDTraceSample = sample
	c.mu.Unlock()
	phase := "recording"
	if sample.ProviderCoverage == "none" {
		c.publish("waiting_provider_registration", false, nil)
		return
	}
	if sample.ProviderCoverage == "partial" {
		phase = "recording_partial"
	}
	c.publish(phase, true, nil)
}
func (c *localWPDTraceController) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		c.step()
		select {
		case <-ctx.Done():
			c.masterChanged(false)
			c.operation.Lock()
			e := c.stopBackend()
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

// Native stop drains consumers before their final counters can be read.
func (c *localWPDTraceController) stopBackend() error {
	err := c.backend.stop()
	c.captureProviderResult()
	return err
}
