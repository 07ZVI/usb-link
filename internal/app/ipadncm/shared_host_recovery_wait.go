package ipadncm

import (
	"context"
	"time"
)

type sharedHostAcquire func(context.Context) (context.Context, func(), bool)
type sharedHostAdmission struct {
	ctx     context.Context
	release func()
	ok      bool
}

// The recovery callback owns only raw USB maintenance, never a normal host
// lease. A normal lease cannot escape until that callback has fully exited.
// Its return is not an online/readiness signal; only the existing raw transport
// may publish attached after admission and NCM initialization.
func acquireHostWithRecovery(ctx context.Context, acquire sharedHostAcquire, recovery func(context.Context)) (context.Context, func(), bool) {
	return acquireHostWithRecoveryAfter(ctx, acquire, recovery, time.After)
}

func acquireHostWithRecoveryAfter(ctx context.Context, acquire sharedHostAcquire, recovery func(context.Context), after func(time.Duration) <-chan time.Time) (context.Context, func(), bool) {
	for ctx.Err() == nil {
		var admission sharedHostAdmission
		if recovery == nil {
			admission.ctx, admission.release, admission.ok = acquire(ctx)
		} else {
			// An already-ready native admission should not open or prompt for a
			// raw USB owner. Waiting briefly also coalesces an ordinary rebuild.
			admitted := make(chan sharedHostAdmission, 1)
			go func() {
				lease, release, ok := acquire(ctx)
				admitted <- sharedHostAdmission{lease, release, ok}
			}()
			var stopRecovery context.CancelFunc
			var recoveryDone chan struct{}
			select {
			case admission = <-admitted:
			case <-after(250 * time.Millisecond):
				if ctx.Err() == nil {
					rawCtx, cancel := context.WithCancel(ctx)
					stopRecovery = cancel
					recoveryDone = make(chan struct{})
					go func() {
						defer close(recoveryDone)
						recovery(rawCtx)
					}()
				}
				// Acquire owns its own context cancellation. Join it even on exit
				// so a late lease can never leak into the next USB owner.
				admission = <-admitted
			}
			if stopRecovery != nil {
				stopRecovery()
				<-recoveryDone
			}
		}
		if !admission.ok {
			return nil, nil, false
		}
		if admission.ctx == nil || admission.release == nil {
			if admission.release != nil {
				admission.release()
			}
			return nil, nil, false
		}
		if ctx.Err() == nil && admission.ctx.Err() == nil {
			return admission.ctx, admission.release, true
		}
		// A host generation may have been invalidated during raw USB cleanup.
		// Never start the ordinary bridge with it; release and await a new lease.
		admission.release()
	}
	return nil, nil, false
}
