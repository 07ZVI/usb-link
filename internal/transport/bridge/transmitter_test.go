package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"suhang/usbnet/internal/transport/ncm"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransmitterBoundsUnresolvedPacketsAndPreservesFIFO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan []byte, 100)
	controls := make(chan [][]byte, 4)
	ready := make(chan struct{})
	for i := 0; i < 70; i++ {
		b := packet(ncm.WindowsIP, ncm.MacIP, false)
		b[20] = byte(i)
		packets <- b
	}
	var peer atomic.Value
	peer.Store(Peer{MTU: 1500})
	updates := make(chan TXCounters, 128)
	written := make(chan byte, 70)
	done := make(chan error, 1)
	tx := Transmitter{ReuseFrames: true, Packets: packets, Controls: controls, PeerReady: ready, Batch: 16, Peer: func() Peer { return peer.Load().(Peer) }, Poll: func() error { return nil }, Changed: func(s TXCounters) {
		select {
		case updates <- s:
		default:
		}
	}, Write: func(frames [][]byte) error {
		for _, f := range frames {
			e, err := ncm.ParseEthernet(f)
			if err != nil {
				return err
			}
			written <- e.Payload[20]
		}
		return nil
	}}
	go func() { done <- tx.Run(ctx) }()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case s := <-updates:
			if s.PendingOverflow == 6 {
				goto resolved
			}
		case <-timeout.C:
			t.Fatal("unresolved queue was not bounded")
		}
	}
resolved:
	peer.Store(Peer{MTU: 1500, MAC: mac})
	close(ready)
	for i := 0; i < 64; i++ {
		select {
		case id := <-written:
			if id != byte(i) {
				t.Fatal("packets overtook unresolved queue", i, id)
			}
		case <-timeout.C:
			t.Fatal("resolved queue not flushed")
		}
	}
	b := packet(ncm.WindowsIP, ncm.MacIP, true)
	b[20] = 99
	packets <- b
	select {
	case id := <-written:
		if id != 99 {
			t.Fatal(id)
		}
	case <-timeout.C:
		t.Fatal("single packet held waiting for a batch")
	}
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestBlockedOUTDoesNotOwnIngressAndCancellationJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan []byte, 1)
	packets <- packet(ncm.WindowsIP, ncm.MacIP, false)
	entered := make(chan struct{})
	done := make(chan error, 1)
	tx := Transmitter{ReuseFrames: true, Packets: packets, Batch: 16, Peer: func() Peer { return Peer{MAC: mac, MTU: 1500} }, Poll: func() error { return nil }, Write: func([][]byte) error { close(entered); <-ctx.Done(); return ctx.Err() }}
	go func() { done <- tx.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("OUT worker never entered")
	}
	// Ingress owns a separate Peer and continues validating/delivering frames
	// while OUT has no free slot. Packet contents remain unchanged.
	receiver := Peer{MTU: 1500}
	original := packet(ncm.MacIP, ncm.WindowsIP, true)
	for i := 0; i < 1000; i++ {
		_, ip := receiver.FromMac(ncm.Frame(ncm.ProbeMAC, mac, 0x800, original))
		if !bytes.Equal(ip, original) {
			t.Fatal("ingress changed while OUT was blocked")
		}
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked writer not joined after cancellation")
	}
}

func TestTransmitterRejectsOutsideAddressesAndPropagatesWriterError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan []byte, 4)
	packets <- packet([4]byte{192, 168, 1, 2}, ncm.MacIP, false)
	packets <- packet(ncm.WindowsIP, ncm.MacIP, false)
	failure := errors.New("USB writer failed")
	var last TXCounters
	tx := Transmitter{Packets: packets, Batch: 16, Peer: func() Peer { return Peer{MAC: mac, MTU: 1500} }, Poll: func() error { return nil }, Write: func(frames [][]byte) error {
		if len(frames) != 1 {
			t.Fatal("outside peer packet admitted")
		}
		return failure
	}, Changed: func(s TXCounters) { last = s }}
	if e := tx.Run(ctx); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	if last.Filtered != 1 || last.Packets != 1 {
		t.Fatal(last)
	}
}

func TestControlQueueCancellationAndFrameOwnership(t *testing.T) {
	queue := make(chan [][]byte, 1)
	ctx, cancel := context.WithCancel(context.Background())
	f := ARPRequest()
	if e := EnqueueControl(ctx, queue, [][]byte{f}); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal((<-queue)[0], f) {
		t.Fatal("control frame changed")
	}
	queue <- [][]byte{f}
	cancel()
	if e := EnqueueControl(ctx, queue, [][]byte{f}); !errors.Is(e, context.Canceled) {
		t.Fatal("full control queue ignored cancellation", e)
	}
}

// Oversize diagnosis must not confuse Ethernet padding, corrupt packets or
// unrelated addresses with a path MTU failure, or change accepted traffic.
func TestTransmitterSeparatesValidatedMTURejections(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprint("reuse=", reuse), func(t *testing.T) {
			makeIP := func(size int, source [4]byte) []byte {
				ip := make([]byte, size)
				copy(ip, packet(source, ncm.MacIP, false))
				binary.BigEndian.PutUint16(ip[2:4], uint16(size))
				ip[10], ip[11] = 0, 0
				binary.BigEndian.PutUint16(ip[10:12], ncm.Checksum(ip[:20]))
				return ip
			}
			jumbo := makeIP(16000, ncm.WindowsIP)
			oversized := makeIP(16001, ncm.WindowsIP)
			corrupt := append([]byte(nil), oversized...)
			corrupt[10] ^= 1
			foreign := makeIP(16001, [4]byte{192, 168, 1, 1})
			// Extra ring storage after the IPv4 datagram is not oversize IP traffic.
			padded := append(append([]byte(nil), jumbo...), make([]byte, 8)...)
			packets := make(chan []byte, 5)
			for _, ip := range [][]byte{jumbo, oversized, corrupt, foreign, padded} {
				packets <- ip
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var final TXCounters
			var delivered [][]byte
			tx := Transmitter{Packets: packets, Batch: 16, ReuseFrames: reuse,
				Peer: func() Peer { return Peer{MTU: 16000, MAC: mac} }, Poll: func() error { return nil },
				Write: func(frames [][]byte) error {
					for _, f := range frames {
						e, err := ncm.ParseEthernet(f)
						if err != nil {
							return err
						}
						delivered = append(delivered, append([]byte(nil), e.Payload...))
					}
					return nil
				},
				Changed: func(s TXCounters) {
					final = s
					if s.Packets+s.Filtered == 5 {
						cancel()
					}
				},
			}
			if err := tx.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if final.Packets != 2 || final.Filtered != 3 || final.MTUExceeded != 1 || final.MTUExceededBytes != 16001 || final.MaxRejectedIPLength != 16001 {
				t.Fatal(final)
			}
			if len(delivered) != 2 || !bytes.Equal(delivered[0], jumbo) || !bytes.Equal(delivered[1], jumbo) {
				t.Fatal("accepted packet content/order changed")
			}
		})
	}
}

// Diagnostic work must exclusively own OUT and return ordinary packet ownership.
func TestDiagnosticWorkResumesPacketsWithoutConcurrentOUT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	work := make(chan func() error, 1)
	packets := make(chan []byte, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var owns atomic.Bool
	work <- func() error {
		owns.Store(true)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		owns.Store(false)
		return nil
	}
	written := make(chan struct{}, 1)
	done := make(chan error, 1)
	tx := Transmitter{Work: work, Packets: packets, Batch: 16, Peer: func() Peer { return Peer{MAC: mac, MTU: 1500} }, Poll: func() error {
		if owns.Load() {
			return errors.New("poll overlapped diagnostic")
		}
		return nil
	}, Write: func([][]byte) error {
		if owns.Load() {
			return errors.New("write overlapped diagnostic")
		}
		written <- struct{}{}
		return nil
	}}
	go func() { done <- tx.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("work never entered")
	}
	packets <- packet(ncm.WindowsIP, ncm.MacIP, false)
	close(release)
	select {
	case <-written:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(time.Second):
		t.Fatal("ordinary packet did not resume")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("OUT owner did not join")
	}
}
func TestDiagnosticNativeFaultPropagatesAndCancellationJoins(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		work := make(chan func() error, 1)
		fault := errors.New("native completion fault")
		work <- func() error {
			if cancelled {
				cancel()
				return ctx.Err()
			}
			return fault
		}
		tx := Transmitter{Work: work, Batch: 1, Peer: func() Peer { return Peer{MAC: mac, MTU: 1500} }, Poll: func() error { return nil }, Write: func([][]byte) error { return nil }}
		expected := fault
		if cancelled {
			expected = context.Canceled
		}
		if e := tx.Run(ctx); !errors.Is(e, expected) {
			t.Fatal(e)
		}
		cancel()
	}
}
