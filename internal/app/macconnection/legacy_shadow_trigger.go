package macconnection

import (
	"context"
	"sync"
)

// One real success event may start a read-only shadow job. Neither this trigger
// nor connection cleanup joins the job; disabled/unready/cancelled events do
// not consume the once. The job must freshly prove its own observation scope.
type macFirewallShadowOnce struct{ once sync.Once }

func (s *macFirewallShadowOnce) tryStart(ctx context.Context, enabled, legacy, connected bool, work func()) bool {
	if ctx == nil || ctx.Err() != nil || !enabled || !legacy || !connected || work == nil {
		return false
	}
	started := false
	s.once.Do(func() {
		started = true
		go work()
	})
	return started
}
