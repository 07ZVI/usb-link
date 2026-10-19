//go:build windows && amd64

package ipadncm

import (
	"context"
)

// Avoid GET_DESCRIPTOR while the old configuration is disappearing. The hub
// cache only schedules a fresh full inventory; it never proves authorization.
func modeArrivalCacheReady(ctx context.Context, target Device) bool {
	cached := inventoryProduct(ctx, target.pid)
	hint := modeArrivalCacheHint{readFailed: ctx.Err() != nil || cached.Error != "", hubErrors: cached.HubErrors, portErrors: cached.ConnectionReadErrors, devices: len(cached.Devices)}
	if len(cached.Devices) == 1 {
		d := cached.Devices[0]
		hint.targetMatches = d.hub == target.hub && d.port == target.port && d.pid == target.pid
		hint.configuration = d.CurrentConfiguration
	}
	ready := hint.permitsFullRead()
	return ready
}
