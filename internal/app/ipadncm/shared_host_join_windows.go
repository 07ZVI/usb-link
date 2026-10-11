//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"sync"
)

type sharedHostJoinOwner struct {
	ctx  context.Context
	join func() error
}

var sharedHostJoin struct {
	sync.Mutex
	owner *sharedHostJoinOwner
}

// SetSharedHostJoin is private process wiring, not a remote permission. The
// callback borrows the actual supervisor generation at the late network join.
func SetSharedHostJoin(ctx context.Context, join func() error) func() {
	o := &sharedHostJoinOwner{ctx, join}
	sharedHostJoin.Lock()
	sharedHostJoin.owner = o
	sharedHostJoin.Unlock()
	return func() {
		sharedHostJoin.Lock()
		if sharedHostJoin.owner == o {
			sharedHostJoin.owner = nil
		}
		sharedHostJoin.Unlock()
	}
}
func joinPreparedSharedHost() error {
	sharedHostJoin.Lock()
	o := sharedHostJoin.owner
	sharedHostJoin.Unlock()
	if o == nil {
		return nil
	}
	if o.ctx.Err() != nil || o.join == nil {
		return fmt.Errorf("APPLICATION_HOST_JOIN_CANCELLED")
	}
	if err := o.join(); err != nil {
		return err
	}
	RecordSharedHostTiming()
	return nil
}
