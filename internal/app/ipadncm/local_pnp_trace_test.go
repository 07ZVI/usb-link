//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"suhang/usbnet/internal/security/deviceguard"
)

type fakePnPSource struct {
	mu     sync.Mutex
	events chan deviceguard.ChangeMetadata
	stats  deviceguard.ChangeMetadataStats
	closed atomic.Bool
}

func (s *fakePnPSource) Events() <-chan deviceguard.ChangeMetadata { return s.events }
func (s *fakePnPSource) Stats() deviceguard.ChangeMetadataStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
func (s *fakePnPSource) StopAdmission() { s.closed.Store(true) }
func waitPnP(t *testing.T, c *localPnPTraceController, predicate func(localPnPTraceStatus) bool) localPnPTraceStatus {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		s := c.snapshot()
		if predicate(s) {
			return s
		}
		select {
		case <-deadline:
			t.Fatal("PnP metadata did not settle", s)
			return s
		case <-time.After(time.Millisecond):
		}
	}
}

func TestPnPMetadataMasterControlsObservationAndClearsOldGeneration(t *testing.T) {
	c := newLocalPnPTraceController()
	var sourcesMu sync.Mutex
	var sources []*fakePnPSource
	var closes atomic.Int32
	c.open = func() (localPnPSource, func(), error) {
		s := &fakePnPSource{events: make(chan deviceguard.ChangeMetadata, 4)}
		sourcesMu.Lock()
		sources = append(sources, s)
		sourcesMu.Unlock()
		return s, func() { closes.Add(1) }, nil
	}
	c.archive = func(string, any) bool { return true }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go c.run(ctx, done)
	t.Cleanup(func() { cancel(); <-done })
	c.master(true)
	if s := waitPnP(t, c, func(s localPnPTraceStatus) bool { return s.Active }); s.Coverage != "not_covered" || s.Received != 0 {
		t.Fatal("subscription claimed event coverage", s)
	}
	sourcesMu.Lock()
	first := sources[0]
	sourcesMu.Unlock()
	first.mu.Lock()
	first.stats.Observed = 1
	first.mu.Unlock()
	first.events <- deviceguard.ChangeMetadata{Sequence: 1, UTC: "2026-10-17T01:02:03Z", Action: "instance_enumerated", NodeKey: "opaque"}
	if s := waitPnP(t, c, func(s localPnPTraceStatus) bool { return s.Received == 1 }); s.Coverage != "metadata_only" || s.TargetScope != "apple_candidate_not_authorization" || s.Archived != 1 {
		t.Fatal(s)
	}
	c.master(false)
	if !first.closed.Load() {
		t.Fatal("closing waited for native unregistration before revoking capture")
	}
	waitPnP(t, c, func(s localPnPTraceStatus) bool { return !s.Active })
	c.master(true)
	if s := waitPnP(t, c, func(s localPnPTraceStatus) bool { return s.Active }); s.Received != 0 || s.Coverage != "not_covered" {
		t.Fatal("old generation appeared current", s)
	}
	if closes.Load() != 1 {
		t.Fatal("old registration was not closed", closes.Load())
	}
}

func TestPnPMetadataUnregistrationAndQueueLossRemainVisible(t *testing.T) {
	c := newLocalPnPTraceController()
	s := &fakePnPSource{events: make(chan deviceguard.ChangeMetadata, 1), stats: deviceguard.ChangeMetadataStats{Observed: 3, QueueDropped: 1, UnregisterFailed: 1}}
	c.open = func() (localPnPSource, func(), error) { return s, func() {}, nil }
	c.archive = func(string, any) bool { return true }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go c.run(ctx, done)
	c.master(true)
	waitPnP(t, c, func(s localPnPTraceStatus) bool { return s.Active })
	c.master(false)
	state := waitPnP(t, c, func(s localPnPTraceStatus) bool { return !s.Active })
	if state.Coverage != "incomplete" || state.QueueDropped != 1 || state.UnregisterFailed != 1 || state.Cancelled != 2 {
		t.Fatal("partial native evidence appeared complete", state)
	}
	cancel()
	<-done
}

func TestPnPMetadataRegistrationFailureDoesNotClaimCoverage(t *testing.T) {
	c := newLocalPnPTraceController()
	c.open = func() (localPnPSource, func(), error) {
		return nil, nil, errors.New("private native path never exported")
	}
	c.archive = func(string, any) bool { return true }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go c.run(ctx, done)
	c.master(true)
	s := waitPnP(t, c, func(s localPnPTraceStatus) bool { return s.Error != "" })
	if s.Active || s.Available || s.Coverage != "not_covered" || s.Error != "PNP_METADATA_SUBSCRIPTION_UNAVAILABLE" {
		t.Fatal(s)
	}
	cancel()
	<-done
}

func TestPnPMetadataCancelledOpenKeepsTailCountsAndBlocksUnconfirmedCleanup(t *testing.T) {
	c := newLocalPnPTraceController()
	s := &fakePnPSource{events: make(chan deviceguard.ChangeMetadata, 2), stats: deviceguard.ChangeMetadataStats{Observed: 2}}
	entered, release := make(chan struct{}), make(chan struct{})
	var opens atomic.Int32
	c.open = func() (localPnPSource, func(), error) {
		opens.Add(1)
		close(entered)
		<-release
		return s, func() { s.mu.Lock(); s.stats.UnregisterFailed = 1; s.mu.Unlock() }, nil
	}
	c.archive = func(string, any) bool { return true }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go c.run(ctx, done)
	t.Cleanup(func() { cancel(); <-done })
	c.master(true)
	<-entered
	c.master(false)
	close(release)
	state := waitPnP(t, c, func(s localPnPTraceStatus) bool { return s.CancelledStarts == 1 })
	if state.Active || state.CancelledBeforeReady != 2 || state.UnregisterFailed != 1 || state.Coverage != "incomplete" || state.Error != "PNP_METADATA_UNREGISTER_UNCONFIRMED" || !s.closed.Load() {
		t.Fatal("cancelled native subscription silently lost its tail", state)
	}
	c.master(true)
	state = c.snapshot()
	if state.Active || state.UnregisterFailed != 1 || state.Error != "PNP_METADATA_UNREGISTER_UNCONFIRMED" || opens.Load() != 1 {
		t.Fatal("unconfirmed old registration was replaced or hidden", state)
	}
}

func TestPnPMetadataCancelledContextNeverRegisters(t *testing.T) {
	c := newLocalPnPTraceController()
	var opens atomic.Int32
	c.open = func() (localPnPSource, func(), error) { opens.Add(1); return nil, nil, errors.New("must not register") }
	c.master(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go c.run(ctx, done)
	<-done
	if opens.Load() != 0 || c.snapshot().Active {
		t.Fatal("cancelled controller registered a native observer")
	}
}

func TestPnPMetadataPartialRegistrationFailureKeepsNativeTail(t *testing.T) {
	c := newLocalPnPTraceController()
	s := &fakePnPSource{events: make(chan deviceguard.ChangeMetadata, 2), stats: deviceguard.ChangeMetadataStats{Observed: 2}}
	c.open = func() (localPnPSource, func(), error) {
		return s, func() { s.mu.Lock(); s.stats.UnregisterFailed = 1; s.mu.Unlock() }, errors.New("second registration failed")
	}
	c.archive = func(string, any) bool { return true }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go c.run(ctx, done)
	t.Cleanup(func() { cancel(); <-done })
	c.master(true)
	state := waitPnP(t, c, func(s localPnPTraceStatus) bool { return s.CancelledStarts == 1 })
	if state.Active || state.CancelledBeforeReady != 2 || state.UnregisterFailed != 1 || state.Coverage != "incomplete" || state.Error != "PNP_METADATA_UNREGISTER_UNCONFIRMED" || !s.closed.Load() {
		t.Fatal("partial registration hid callback loss or live native registration", state)
	}
}
