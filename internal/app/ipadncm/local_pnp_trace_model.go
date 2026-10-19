//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"sync"
	"time"

	"suhang/usbnet/internal/security/deviceguard"
)

type localPnPTraceStatus struct {
	Available               bool   `json:"available"`
	Requested               bool   `json:"requested"`
	Active                  bool   `json:"active"`
	Coverage                string `json:"coverage"`
	TargetScope             string `json:"target_scope"`
	Error                   string `json:"error,omitempty"`
	StartedUTC              string `json:"started_utc,omitempty"`
	SubscriptionsReadyUTC   string `json:"subscriptions_ready_utc,omitempty"`
	LastEventUTC            string `json:"last_event_utc,omitempty"`
	StoppedUTC              string `json:"stopped_utc,omitempty"`
	Received                uint64 `json:"received"`
	Archived                uint64 `json:"archived"`
	ArchiveRejected         uint64 `json:"archive_rejected"`
	QueueDropped            uint64 `json:"queue_dropped"`
	Rejected                uint64 `json:"rejected"`
	RejectedSize            uint64 `json:"rejected_size"`
	RejectedInstance        uint64 `json:"rejected_instance_metadata"`
	RejectedInterface       uint64 `json:"rejected_interface_metadata"`
	UnregisterFailed        uint64 `json:"unregister_failed"`
	Cancelled               uint64 `json:"cancelled_events"`
	CancelledStarts         uint64 `json:"cancelled_starts"`
	CancelledBeforeReady    uint64 `json:"cancelled_before_ready"`
	CancelledStartDrops     uint64 `json:"cancelled_start_queue_dropped"`
	TimestampMeaning        string `json:"timestamp_meaning"`
	SequenceMeaning         string `json:"sequence_meaning"`
	PreSubscriptionCoverage string `json:"pre_subscription_coverage"`
}

type localPnPSource interface {
	Events() <-chan deviceguard.ChangeMetadata
	Stats() deviceguard.ChangeMetadataStats
	StopAdmission()
}

type localPnPTraceController struct {
	mu                 sync.Mutex
	revision           uint64
	wake               chan struct{}
	state              localPnPTraceStatus
	source             localPnPSource
	open               func() (localPnPSource, func(), error)
	archive            func(string, any) bool
	published          bool
	lastPublished      localPnPTraceStatus
	cleanupUnconfirmed bool
}

func newLocalPnPTraceController() *localPnPTraceController {
	return &localPnPTraceController{wake: make(chan struct{}, 1), state: localPnPTraceStatus{Coverage: "not_covered", TargetScope: "apple_candidate_not_authorization", TimestampMeaning: "windows_callback_time_not_ipad_prompt_time", SequenceMeaning: "queue_admission_order_not_kernel_or_prompt_order", PreSubscriptionCoverage: "unknown"}}
}

func (c *localPnPTraceController) master(on bool) {
	c.mu.Lock()
	if c.state.Requested == on {
		c.mu.Unlock()
		return
	}
	c.state.Requested = on
	c.revision++
	if c.source != nil {
		c.source.StopAdmission()
	}
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *localPnPTraceController) snapshot() localPnPTraceStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *localPnPTraceController) publish() {
	c.mu.Lock()
	state := c.state
	if c.published && c.lastPublished == state {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	if c.archive != nil && c.archive("pnp_native_trace_status", state) {
		c.mu.Lock()
		c.lastPublished = state
		c.published = true
		c.mu.Unlock()
	}
}

// Registration can deliver callbacks before it returns, even if the second
// filter fails. Preserve that tail and any failed unregistration in all exits.
func (c *localPnPTraceController) finalizeCancelledSource(source localPnPSource, closeSource func()) {
	if source == nil {
		return
	}
	source.StopAdmission()
	if closeSource != nil {
		closeSource()
	}
	s := source.Stats()
	c.mu.Lock()
	c.state.CancelledStarts++
	if s.Observed >= s.QueueDropped {
		c.state.CancelledBeforeReady += s.Observed - s.QueueDropped
	}
	c.state.CancelledStartDrops += s.QueueDropped
	if s.Observed > 0 || s.QueueDropped > 0 {
		c.state.Coverage = "incomplete"
	}
	if s.UnregisterFailed > 0 {
		c.state.UnregisterFailed += s.UnregisterFailed
		c.state.Error = "PNP_METADATA_UNREGISTER_UNCONFIRMED"
		c.state.Coverage = "incomplete"
		c.cleanupUnconfirmed = true
	}
	c.mu.Unlock()
	c.publish()
}

func (c *localPnPTraceController) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	var processed uint64
	for {
		if ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		revision, on := c.revision, c.state.Requested
		c.mu.Unlock()
		if revision == processed {
			select {
			case <-ctx.Done():
				return
			case <-c.wake:
				continue
			}
		}
		processed = revision
		if !on {
			continue
		}
		c.mu.Lock()
		blocked := c.cleanupUnconfirmed
		c.mu.Unlock()
		if blocked {
			c.publish()
			continue
		}
		startedUTC := time.Now().UTC().Format(time.RFC3339Nano)
		source, closeSource, err := c.open()
		if err != nil {
			c.mu.Lock()
			if c.revision == revision {
				c.state.Error = "PNP_METADATA_SUBSCRIPTION_UNAVAILABLE"
				c.state.Coverage = "not_covered"
			}
			c.mu.Unlock()
			c.finalizeCancelledSource(source, closeSource)
			c.publish()
			continue
		}
		c.mu.Lock()
		if c.revision != revision || ctx.Err() != nil {
			c.mu.Unlock()
			c.finalizeCancelledSource(source, closeSource)
			continue
		}
		c.source = source
		requested := c.state.Requested
		previous := c.state
		c.state = newLocalPnPTraceController().state
		c.state.CancelledStarts, c.state.CancelledBeforeReady, c.state.CancelledStartDrops = previous.CancelledStarts, previous.CancelledBeforeReady, previous.CancelledStartDrops
		c.state.Available, c.state.Active, c.state.Requested = true, true, requested
		c.state.StartedUTC = startedUTC
		c.state.SubscriptionsReadyUTC = time.Now().UTC().Format(time.RFC3339Nano)
		c.mu.Unlock()
		c.publish()
		ticker := time.NewTicker(time.Second)
		stop := false
		for !stop {
			select {
			case <-ctx.Done():
				stop = true
			case <-c.wake:
				c.mu.Lock()
				stop = c.revision != revision
				c.mu.Unlock()
			case e, ok := <-source.Events():
				if !ok {
					c.mu.Lock()
					c.state.Error = "PNP_METADATA_SOURCE_CLOSED"
					c.state.Coverage = "incomplete"
					c.mu.Unlock()
					stop = true
					continue
				}
				c.mu.Lock()
				if c.revision == revision && ctx.Err() == nil {
					c.state.Received++
					c.state.LastEventUTC = e.UTC
					c.state.Coverage = "metadata_only"
					if c.archive != nil && c.archive("pnp_native_metadata", e) {
						c.state.Archived++
					} else {
						c.state.ArchiveRejected++
					}
					if c.state.QueueDropped > 0 || c.state.Rejected > 0 || c.state.ArchiveRejected > 0 || c.state.UnregisterFailed > 0 {
						c.state.Coverage = "incomplete"
					}
				}
				c.mu.Unlock()
			case <-ticker.C:
				c.refresh(source)
				c.publish()
			}
		}
		ticker.Stop()
		source.StopAdmission()
		closeSource()
		c.refresh(source)
		c.mu.Lock()
		c.source = nil
		c.state.Active = false
		c.state.StoppedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		s := source.Stats()
		if s.UnregisterFailed > 0 {
			c.cleanupUnconfirmed = true
			c.state.Error = "PNP_METADATA_UNREGISTER_UNCONFIRMED"
		}
		if s.Observed >= s.QueueDropped && s.Observed-s.QueueDropped > c.state.Received {
			c.state.Cancelled = s.Observed - s.QueueDropped - c.state.Received
			c.state.Coverage = "incomplete"
		}
		c.mu.Unlock()
		c.publish()
		if ctx.Err() != nil {
			return
		}
	}
}

func (c *localPnPTraceController) refresh(source localPnPSource) {
	s := source.Stats()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.QueueDropped = s.QueueDropped
	c.state.Rejected = s.Rejected
	c.state.RejectedSize = s.RejectedSize
	c.state.RejectedInstance = s.RejectedInstance
	c.state.RejectedInterface = s.RejectedInterface
	c.state.UnregisterFailed = s.UnregisterFailed
	if s.QueueDropped > 0 || s.Rejected > 0 || s.UnregisterFailed > 0 || c.state.ArchiveRejected > 0 {
		c.state.Coverage = "incomplete"
	}
}
