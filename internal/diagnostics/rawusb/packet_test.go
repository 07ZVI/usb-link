package rawusb

import (
	"bytes"
	"encoding/binary"
	"suhang/usbnet/internal/transport/ncm"
	"sync"
	"testing"
)

func TestRawFramesAreLegalAndFitAdvertisedNTB(t *testing.T) {
	var nonce [16]byte
	copy(nonce[:], "0123456789abcdef")
	mac := [6]byte{2, 4, 6, 8, 10, 12}
	p := ncm.Parameters{OutMax: 32764, OutAlignment: 4, OutDivisor: 4, OutDatagrams: 16}
	f, e := Frame(16000, nonce, mac)
	if e != nil {
		t.Fatal(e)
	}
	n, e := ncm.BatchLimit(p, len(f), 16)
	if e != nil || n != 2 {
		t.Fatal(n, e)
	}
	frames := [][]byte{append([]byte(nil), f...), append([]byte(nil), f...)}
	for i := range frames {
		FrameSequence(frames[i], uint64(i))
		ip := frames[i][14:]
		if ncm.Checksum(ip[:20]) != 0 || be.Uint16(ip[2:4]) != 16000 || be.Uint16(ip[6:8]) != 0x4000 || be.Uint16(ip[24:26]) != 15980 || be.Uint16(ip[26:28]) != 0 {
			t.Fatal("invalid IPv4/UDP header")
		}
	}
	wire, e := ncm.Encode(frames, 2, p)
	if e != nil || len(wire) > 32764 {
		t.Fatal(e, len(wire))
	}
	out, e := ncm.Decode(wire)
	if e != nil || len(out.Frames) != 2 {
		t.Fatal(e)
	}
	for i, f := range out.Frames {
		seq, flow, ok := Identity(f[42:], nonce)
		if !ok || seq != uint64(i) || flow != 0 {
			t.Fatal("packet identity")
		}
	}
}
func inputFrame(nonce [16]byte, mac [6]byte, flow byte) []byte {
	f, _ := Frame(InputIPLength, nonce, mac)
	copy(f[:6], ncm.ProbeMAC[:])
	copy(f[6:12], mac[:])
	ip := f[14:]
	copy(ip[12:16], ncm.MacIP[:])
	copy(ip[16:20], ncm.WindowsIP[:])
	be.PutUint16(ip[20:22], Port+1+uint16(flow))
	ip[10], ip[11] = 0, 0
	be.PutUint16(ip[10:12], ncm.Checksum(ip[:20]))
	ip[28+32] = flow
	return f
}
func TestInputRejectsWrongPeerNonceFragmentAndPort(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 7
	mac := [6]byte{2, 4, 6, 8, 10, 12}
	good := inputFrame(nonce, mac, 3)
	if p, ok := Input(good, nonce, mac); !ok || len(p) != InputIPLength-28 {
		t.Fatal("valid input rejected")
	}
	for _, offset := range []int{0, 6, 12, 14, 16, 20, 26, 30, 34, 36, 38, 42, 50, 74} {
		b := append([]byte(nil), good...)
		b[offset] ^= 1
		if offset >= 14 && offset < 34 {
			b[24], b[25] = 0, 0
			binary.BigEndian.PutUint16(b[24:26], ncm.Checksum(b[14:34]))
		}
		if _, ok := Input(b, nonce, mac); ok {
			t.Fatalf("accepted mutation at %d", offset)
		}
	}
}
func TestCounterDeduplicatesReorderingAndStops(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 1
	p, _ := Payload(8000, nonce, 0)
	c := NewCounter()
	for _, seq := range []uint64{2, 0, 1, 1, sequenceBits} {
		Sequence(p, seq)
		if !c.Add(p, nonce) {
			t.Fatal("rejected")
		}
	}
	x := c.Stop()
	if x.Packets != 5 || x.UniquePackets != 3 || x.Duplicates != 1 || x.Reordered != 2 || x.SequenceOverflow != 1 || x.UniquePayloadBytes != 3*uint64(len(p)) {
		t.Fatal(x)
	}
	Sequence(p, 3)
	c.Add(p, nonce)
	if c.Snapshot() != x {
		t.Fatal("changed stopped count")
	}
	bad := nonce
	bad[0]++
	if c.Add(p, bad) {
		t.Fatal("wrong nonce consumed")
	}
}
func TestConcurrentCounterAndCorruptionSampling(t *testing.T) {
	var nonce [16]byte
	c := NewCounter()
	var wg sync.WaitGroup
	for flow := byte(0); flow < 4; flow++ {
		wg.Add(1)
		go func(flow byte) {
			defer wg.Done()
			p, _ := Payload(8000, nonce, flow)
			for i := uint64(0); i < 16; i++ {
				Sequence(p, i)
				if i == 0 {
					p[Header] ^= 1
				}
				c.Add(p, nonce)
				if i == 0 {
					p[Header] ^= 1
				}
			}
		}(flow)
	}
	wg.Wait()
	x := c.Stop()
	if x.UniquePackets != 64 || x.CorruptSamples != 4 || x.Duplicates != 0 {
		t.Fatal(x)
	}
	if !bytes.Equal(magic[:], []byte("USBRAW49")) {
		t.Fatal("protocol changed")
	}
}
