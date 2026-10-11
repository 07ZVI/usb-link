package ipadncm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RecoveryTestControl stops only the currently registered Mac attempt. It
// cannot cancel a replacement attempt, the parent, or another USB device.
type RecoveryTestControl struct {
	mu         sync.Mutex
	generation uint64
	ctx        context.Context
	stop       context.CancelFunc
	pending    bool
}

func (c *RecoveryTestControl) Attach(ctx context.Context, stop context.CancelFunc) func() {
	c.mu.Lock()
	c.generation++
	generation := c.generation
	c.ctx, c.stop = ctx, stop
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.generation == generation {
			c.ctx, c.stop = nil, nil
		}
	}
}
func (c *RecoveryTestControl) Request() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending || c.ctx == nil || c.ctx.Err() != nil || c.stop == nil {
		return fmt.Errorf("active Mac attempt required; recovery test unavailable")
	}
	c.pending = true
	generation := c.generation
	// Allow the authenticated acknowledgement to leave before teardown begins.
	time.AfterFunc(200*time.Millisecond, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.pending && c.generation == generation && c.ctx != nil && c.ctx.Err() == nil {
			c.stop()
		}
	})
	return nil
}
func (c *RecoveryTestControl) Consume() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	pending := c.pending
	c.pending = false
	return pending
}
