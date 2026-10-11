package bridge

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTransmitterReleasesWholeBatchOnWriteFailure(t *testing.T) {
	packets := make(chan []byte, 8)
	released := map[*byte]int{}
	for i := 0; i < 8; i++ {
		p := variedPacket(200+i, i)
		if i%3 == 0 {
			p[10] ^= 1
		}
		packets <- p
		released[&p[0]] = 0
	}
	failure := errors.New("USB failed")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tx := Transmitter{Packets: packets, Batch: 8, Peer: func() Peer { return Peer{MAC: mac, MTU: 16000} }, ReuseFramesNow: func() bool { return true }, ReleasePacket: func(p []byte) { released[&p[0]]++ }, Write: func(frames [][]byte) error {
		if len(frames) != 5 {
			t.Fatal(len(frames))
		}
		return failure
	}, Poll: func() error { return nil }}
	if e := tx.Run(ctx); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	for _, n := range released {
		if n != 1 {
			t.Fatal("release count", n)
		}
	}
}
func TestTransmitterReleasesPendingOnCancellationAndOverflow(t *testing.T) {
	packets := make(chan []byte, 70)
	released := map[*byte]int{}
	for i := 0; i < 70; i++ {
		p := variedPacket(100, i)
		packets <- p
		released[&p[0]] = 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tx := Transmitter{Packets: packets, Batch: 16, Peer: func() Peer { return Peer{MTU: 1500} }, ReleasePacket: func(p []byte) { released[&p[0]]++ }, Write: func([][]byte) error { t.Fatal("unresolved packet sent"); return nil }, Poll: func() error { return nil }, Changed: func(s TXCounters) {
		if s.PendingOverflow == 6 {
			cancel()
		}
	}}
	if e := tx.Run(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, n := range released {
		if n != 1 {
			t.Fatal("pending release count", n)
		}
	}
}
func TestFrameReuseSwitchPreservesPacketBytes(t *testing.T) {
	packets := make(chan []byte, 8)
	for i := 0; i < 8; i++ {
		packets <- variedPacket(200+i, i)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sent := 0
	reuse := false
	tx := Transmitter{Packets: packets, Batch: 1, Peer: func() Peer { return Peer{MAC: mac, MTU: 1500} }, ReuseFramesNow: func() bool { reuse = !reuse; return reuse }, Poll: func() error { return nil }, Write: func(frames [][]byte) error {
		want := variedPacket(200+sent, sent)
		p, e := IPv4(frames[0][14:], 1500)
		if e != nil || string(p) != string(want) {
			t.Fatal("mode changed bytes", e)
		}
		sent++
		if sent == 8 {
			cancel()
		}
		return nil
	}}
	if e := tx.Run(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
