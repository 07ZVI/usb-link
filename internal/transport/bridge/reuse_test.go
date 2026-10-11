package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"suhang/usbnet/internal/transport/ncm"
	"testing"
)

func variedPacket(length, id int) []byte {
	b := make([]byte, length)
	copy(b, packet(ncm.WindowsIP, ncm.MacIP, id%2 == 0))
	binary.BigEndian.PutUint16(b[2:], uint16(length))
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:], ncm.Checksum(b[:20]))
	for i := 20; i < length; i++ {
		b[i] = byte(id + i)
	}
	return b
}

func TestFrameReuseMatchesIndependentBytesAndClearsPadding(t *testing.T) {
	p := Peer{MAC: mac, MTU: 1500}
	storage := bytes.Repeat([]byte{0xee}, 1514)
	for _, size := range []int{1500, 20, 46, 61, 1499, 20} {
		ip := variedPacket(size, size)
		original := append([]byte(nil), ip...)
		want := make([]byte, max(60, 14+size))
		copy(want, mac[:])
		copy(want[6:], ncm.ProbeMAC[:])
		binary.BigEndian.PutUint16(want[12:], 0x800)
		copy(want[14:], ip)
		got, err := p.FromWindowsInto(ip, storage)
		if err != nil || !bytes.Equal(got, want) || !bytes.Equal(ip, original) {
			t.Fatalf("size %d: %v", size, err)
		}
		storage = got
	}
	ip := variedPacket(1500, 1)
	if n := testing.AllocsPerRun(100, func() {
		if _, e := p.FromWindowsInto(ip, storage); e != nil {
			panic(e)
		}
	}); n != 0 {
		t.Fatalf("frame allocations: %v", n)
	}
}

func TestReusableTransmitterMatchesOwnedFramesAndRejectsSamePackets(t *testing.T) {
	inputs := make([][]byte, 60)
	for i := range inputs {
		inputs[i] = variedPacket(20+(i*97)%1481, i)
		if i%5 == 0 {
			inputs[i][10] ^= 1
		}
	}
	run := func(reuse bool) ([][]byte, TXCounters) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		packets := make(chan []byte, len(inputs))
		for _, ip := range inputs {
			packets <- ip
		}
		var output [][]byte
		var last TXCounters
		var seq uint16
		tx := Transmitter{Packets: packets, ReuseFrames: reuse, Batch: 4,
			Peer: func() Peer { return Peer{MAC: mac, MTU: 1500} }, Poll: func() error { return nil },
			Write: func(frames [][]byte) error {
				block, e := ncm.Encode(frames, seq, ncm.Parameters{OutMax: 32764, OutAlignment: 4, OutDivisor: 4})
				seq++
				output = append(output, block)
				return e
			}, Changed: func(s TXCounters) {
				last = s
				if s.Packets+s.Filtered == uint64(len(inputs)) {
					cancel()
				}
			},
		}
		if e := tx.Run(ctx); !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
		return output, last
	}
	want, ws := run(false)
	got, gs := run(true)
	if ws != gs || ws.Packets != 48 || ws.Filtered != 12 || len(want) != len(got) {
		t.Fatalf("counters/batches: %+v %+v", ws, gs)
	}
	for i := range want {
		if !bytes.Equal(want[i], got[i]) {
			t.Fatalf("batch %d changed bytes/order", i)
		}
	}
	for i, ip := range inputs {
		want := variedPacket(20+(i*97)%1481, i)
		if i%5 == 0 {
			want[10] ^= 1
		}
		if !bytes.Equal(ip, want) {
			t.Fatal("source packet mutated", i)
		}
	}
}

func BenchmarkOutboundFrame(b *testing.B) {
	p := Peer{MAC: mac, MTU: 1500}
	ip := variedPacket(1500, 1)
	for _, reuse := range []bool{false, true} {
		name := "owned"
		if reuse {
			name = "reuse"
		}
		b.Run(name, func(b *testing.B) {
			storage := make([]byte, 1514)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var e error
				if reuse {
					_, e = p.FromWindowsInto(ip, storage)
				} else {
					_, e = p.FromWindows(ip)
				}
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
