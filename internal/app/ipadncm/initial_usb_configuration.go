package ipadncm

import (
	"context"
	"strings"
	"time"
)

// This private identity scopes a wait, never a USB permission.
type initialUSBConfigurationTarget struct {
	root, hub, serial, product string
	port                       uint32
	pid, bcd                   uint16
}

func (a initialUSBConfigurationTarget) same(b initialUSBConfigurationTarget) bool {
	return a.root != "" && a.hub != "" && a.port != 0 && a.serial != "" && a.product != "" && a.pid == 0x12ab &&
		strings.EqualFold(a.root, b.root) && strings.EqualFold(a.hub, b.hub) && a.port == b.port && a.pid == b.pid && a.bcd == b.bcd && a.serial == b.serial && a.product == b.product
}

// Only the cached wait has this deadline. A subsequent full identity read has
// its existing timeout and may take longer; it runs at most once.
func awaitInitialUSBConfiguration(ctx context.Context, notices <-chan struct{}, limit, fallback time.Duration, sample func(context.Context) string, verify func() bool) string {
	waitCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		if ctx.Err() != nil {
			return "INITIAL_CONFIGURATION_CANCELLED"
		}
		if waitCtx.Err() != nil {
			return "INITIAL_CONFIGURATION_TIMEOUT"
		}
		state := sample(waitCtx)
		if ctx.Err() != nil {
			return "INITIAL_CONFIGURATION_CANCELLED"
		}
		if waitCtx.Err() != nil {
			return "INITIAL_CONFIGURATION_TIMEOUT"
		}
		if state == "INITIAL_CONFIGURATION_CACHE_READY" {
			cancel()
			verified := verify()
			if ctx.Err() != nil {
				return "INITIAL_CONFIGURATION_CANCELLED"
			}
			if !verified {
				return "INITIAL_CONFIGURATION_FULL_PROOF_FAILED"
			}
			return "INITIAL_CONFIGURATION_VERIFIED_NOT_AUTHORIZED"
		}
		if state != "INITIAL_CONFIGURATION_ZERO" {
			return state
		}
		timer := time.NewTimer(fallback)
		select {
		case <-waitCtx.Done():
			timer.Stop()
		case _, open := <-notices:
			timer.Stop()
			if !open {
				notices = nil
			}
		case <-timer.C:
		}
	}
}
