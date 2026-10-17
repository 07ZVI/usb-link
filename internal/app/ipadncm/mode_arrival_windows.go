//go:build windows && amd64

package ipadncm

import (
	"context"
	"time"
)

// Avoid GET_DESCRIPTOR while the old configuration is disappearing. The hub
// cache only schedules a fresh full inventory; it never proves authorization.
func modeArrivalCacheReady(ctx context.Context, target Device) bool {
	started := time.Now()
	cached := inventoryProduct(ctx, target.pid)
	hint := modeArrivalCacheHint{readFailed: ctx.Err() != nil || cached.Error != "", hubErrors: cached.HubErrors, portErrors: cached.ConnectionReadErrors, devices: len(cached.Devices)}
	if len(cached.Devices) == 1 {
		d := cached.Devices[0]
		hint.targetMatches = d.hub == target.hub && d.port == target.port && d.pid == target.pid
		hint.configuration = d.CurrentConfiguration
	}
	ready := hint.permitsFullRead()
	RecordConnectionArchiveEvent("mode_cache_sample", struct {
		Attempt        uint64   `json:"software_attempt"`
		StartedUTC     string   `json:"read_started_utc"`
		ElapsedMS      int64    `json:"read_elapsed_ms"`
		FullCheckDue   bool     `json:"full_identity_check_eligible_not_authorized"`
		CachedReadOnly bool     `json:"cached_connection_information_only"`
		USB            Snapshot `json:"usb"`
	}{currentSoftwareAttempt(), started.UTC().Format(time.RFC3339Nano), time.Since(started).Milliseconds(), ready, true, cached})
	return ready
}
