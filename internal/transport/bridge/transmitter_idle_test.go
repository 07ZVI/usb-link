package bridge

import (
	"context"
	"errors"
	"suhang/usbnet/internal/transport/ncm"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransmitterDoesNotPollWithoutPendingTransfers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var polls atomic.Int32
	tx := Transmitter{Batch: 1, Peer: func() Peer { return Peer{} }, Write: func([][]byte) error { return nil }, Poll: func() error { polls.Add(1); return nil }, Pending: func() bool { return false }}
	done := make(chan error, 1)
	go func() { done <- tx.Run(ctx) }()
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("idle transmitter ignored cancellation")
	}
	if n := polls.Load(); n != 0 {
		t.Fatalf("idle completion polling: %d", n)
	}
}

func TestTransmitterCollectsCompletionThenStopsIdlePolling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controls := make(chan [][]byte, 1)
	var pending atomic.Bool
	var polls atomic.Int32
	collected := make(chan struct{}, 1)
	tx := Transmitter{Batch: 1, Controls: controls, Peer: func() Peer { return Peer{} }, Write: func([][]byte) error { pending.Store(true); return nil }, Pending: pending.Load, Poll: func() error { polls.Add(1); pending.Store(false); collected <- struct{}{}; return nil }}
	done := make(chan error, 1)
	go func() { done <- tx.Run(ctx) }()
	controls <- [][]byte{{1}}
	select {
	case <-collected:
	case <-time.After(time.Second):
		t.Fatal("pending completion never collected")
	}
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("transmitter ignored cancellation")
	}
	if n := polls.Load(); n != 1 {
		t.Fatalf("completion timer remained active after draining: %d", n)
	}
}

// Exercise the exact gap between checking Pending and select. A producer can
// enqueue here after idle polling was disabled; the packet channel itself must
// wake OUT, with no timer or second packet required.
func TestPacketQueuedDuringPendingCheckWakesIdleTransmitter(t *testing.T) {
	for _, control := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		packets := make(chan []byte, 1)
		controls := make(chan [][]byte, 1)
		checked, release := make(chan struct{}), make(chan struct{})
		written := make(chan struct{}, 1)
		var calls atomic.Int32
		var polls atomic.Int32
		tx := Transmitter{Batch: 1, Packets: packets, Controls: controls, Peer: func() Peer { return Peer{MAC: mac, MTU: 1500} }, Pending: func() bool {
			if calls.Add(1) == 1 {
				close(checked)
				<-release
			}
			return false
		}, Poll: func() error { polls.Add(1); return nil }, Write: func([][]byte) error { written <- struct{}{}; return nil }}
		done := make(chan error, 1)
		go func() { done <- tx.Run(ctx) }()
		<-checked
		if control {
			controls <- [][]byte{ARPRequest()}
		} else {
			packets <- packet(ncm.WindowsIP, ncm.MacIP, false)
		}
		close(release)
		select {
		case <-written:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("queued packet lost between Pending and select")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if polls.Load() != 0 {
			t.Fatal("packet was rescued by timer instead of channel")
		}
	}
}
