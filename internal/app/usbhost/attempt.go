package usbhost

import (
	"context"
	"fmt"
	"sync"
)

// AttemptLease permits device preparation before the host exists, then holds
// the real host generation through device cleanup. It is not a host proof.
type AttemptLease struct {
	sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	acquire          func(context.Context) (context.Context, func(), bool)
	host             context.Context
	release          func()
	stopInvalidation func() bool
	closed           bool
}

func NewAttemptLease(parent context.Context, acquire func(context.Context) (context.Context, func(), bool)) *AttemptLease {
	ctx, cancel := context.WithCancel(parent)
	return &AttemptLease{ctx: ctx, cancel: cancel, acquire: acquire}
}
func (a *AttemptLease) Context() context.Context { return a.ctx }
func (a *AttemptLease) Cancel()                  { a.cancel() }
func (a *AttemptLease) Join() error {
	a.Lock()
	defer a.Unlock()
	if a.closed || a.ctx.Err() != nil {
		return fmt.Errorf("HOST_ATTEMPT_CANCELLED")
	}
	if a.host != nil {
		if a.host.Err() != nil {
			return fmt.Errorf("HOST_GENERATION_CHANGED")
		}
		return nil
	}
	host, release, ok := a.acquire(a.ctx)
	if !ok || host == nil || release == nil {
		return fmt.Errorf("HOST_JOIN_CANCELLED")
	}
	a.host, a.release = host, release
	a.stopInvalidation = context.AfterFunc(host, a.cancel)
	if host.Err() != nil {
		a.cancel()
		return fmt.Errorf("HOST_GENERATION_CHANGED")
	}
	return a.ctx.Err()
}
func (a *AttemptLease) Invalidated() bool {
	a.Lock()
	defer a.Unlock()
	return a.host != nil && a.host.Err() != nil
}

// Close is called only after bridge/application cleanup has joined. A host
// generation cannot close under a still-live device session's borrowed lease.
func (a *AttemptLease) Close() {
	a.cancel()
	a.Lock()
	defer a.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	if a.stopInvalidation != nil {
		a.stopInvalidation()
	}
	if a.release != nil {
		a.release()
	}
}
