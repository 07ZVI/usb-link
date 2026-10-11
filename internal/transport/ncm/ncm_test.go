package ncm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func params() Parameters {
	return Parameters{Formats: 1, InMax: 16384, InDivisor: 4, InAlignment: 4, OutMax: 16384, OutDivisor: 16, OutRemainder: 2, OutAlignment: 8}
}
func TestNTBMultiAndAlignment(t *testing.T) {
	p := params()
	fs := [][]byte{EchoRequest([6]byte{2, 3, 4, 5, 6, 7}, 1), make([]byte, 1514)}
	b, e := Encode(fs, 65535, p)
	if e != nil {
		t.Fatal(e)
	}
	x, e := Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	if x.Sequence != 65535 || len(x.Frames) != 2 {
		t.Fatal(x)
	}
	for i, f := range fs {
		if !bytes.Equal(f, x.Frames[i]) {
			t.Fatal("corrupt frame")
		}
		ndp := int(binary.LittleEndian.Uint16(b[10:]))
		off := int(binary.LittleEndian.Uint16(b[ndp+8+i*4:]))
		if (off+14)%16 != 2 {
			t.Fatal("bad payload alignment")
		}
	}
}
func TestChainedNDP(t *testing.T) {
	b := make([]byte, 164)
	copy(b, "NCMH")
	le.PutUint16(b[4:], 12)
	le.PutUint16(b[8:], 164)
	le.PutUint16(b[10:], 12)
	for i, ndp := range []int{12, 28} {
		copy(b[ndp:], "NCM0")
		le.PutUint16(b[ndp+4:], 16)
		le.PutUint16(b[ndp+8:], uint16(44+i*60))
		le.PutUint16(b[ndp+10:], 60)
	}
	le.PutUint16(b[18:], 28)
	x, e := Decode(b)
	if e != nil || len(x.Frames) != 2 {
		t.Fatal(x, e)
	}
	le.PutUint16(b[34:], 12)
	if _, e = Decode(b); e == nil {
		t.Fatal("cycle accepted")
	}
}
func TestStreamChunksAndBlocks(t *testing.T) {
	b, e := Encode([][]byte{EchoRequest([6]byte{2}, 1)}, 1, params())
	if e != nil {
		t.Fatal(e)
	}
	for cut := 0; cut <= len(b); cut++ {
		s := Stream{}
		a, e := s.Feed(b[:cut])
		if e != nil {
			t.Fatal(e)
		}
		c, e := s.Feed(append(append([]byte(nil), b[cut:]...), b...))
		if e != nil || len(a)+len(c) != 2 || len(s.Pending) != 0 {
			t.Fatal(cut, e)
		}
	}
}
func TestMalformed(t *testing.T) {
	b, _ := Encode([][]byte{make([]byte, 60)}, 1, params())
	for _, mut := range []func([]byte){func(b []byte) { b[4] = 10 }, func(b []byte) { b[8] = 1 }, func(b []byte) { b[10] = 13 }, func(b []byte) { b[16] = 'X' }, func(b []byte) { b[28] = 1 }, func(b []byte) { b[24] = 255; b[25] = 255 }, func(b []byte) { b[24] = 12; b[25] = 0 }} {
		x := append([]byte(nil), b...)
		mut(x)
		if _, e := Decode(x); e == nil {
			t.Fatal("invalid NTB accepted", x)
		}
	}
}
func TestARPAndICMP(t *testing.T) {
	mac := [6]byte{2, 3, 4, 5, 6, 7}
	a := make([]byte, 28)
	be.PutUint16(a, 1)
	be.PutUint16(a[2:], 0x800)
	a[4] = 6
	a[5] = 4
	be.PutUint16(a[6:], 1)
	copy(a[8:], mac[:])
	copy(a[14:], MacIP[:])
	copy(a[24:], WindowsIP[:])
	r, learned, e := ARPReply(Frame([6]byte{255, 255, 255, 255, 255, 255}, mac, 0x806, a))
	if e != nil || learned != mac {
		t.Fatal(e)
	}
	eth, _ := ParseEthernet(r)
	if eth.Destination != mac || be.Uint16(eth.Payload[6:]) != 2 || !bytes.Equal(eth.Payload[14:18], WindowsIP[:]) {
		t.Fatal(eth)
	}
	a[27] = 3
	r, _, _ = ARPReply(Frame(mac, mac, 0x806, a))
	if r != nil {
		t.Fatal("answered unrelated ARP")
	}
	request := EchoRequest(mac, 9)
	_, ip, e := IPv4ICMP(request)
	if e != nil || ip == nil {
		t.Fatal(e)
	}
	copy(ip[12:], MacIP[:])
	copy(ip[16:], WindowsIP[:])
	ip[10] = 0
	ip[11] = 0
	be.PutUint16(ip[10:], Checksum(ip[:20]))
	reply := EchoReply(Frame(ProbeMAC, mac, 0x800, ip))
	_, echoed, err := IPv4ICMP(reply)
	if reply == nil || err != nil || echoed == nil || echoed[20] != 0 || !bytes.Equal(echoed[12:16], WindowsIP[:]) || !bytes.Equal(echoed[16:20], MacIP[:]) {
		t.Fatal("Mac ping reply", err)
	}
	copy(echoed[12:], MacIP[:])
	copy(echoed[16:], WindowsIP[:])
	echoed[10] = 0
	echoed[11] = 0
	be.PutUint16(echoed[10:], Checksum(echoed[:20]))
	reply = Frame(ProbeMAC, mac, 0x800, echoed)
	if !IsProbeEchoReply(reply, 9) {
		t.Fatal("probe reply validation")
	}
	reply[35] ^= 1
	if IsProbeEchoReply(reply, 9) {
		t.Fatal("invalid checksum accepted")
	}
}
func TestDescriptorAndParameters(t *testing.T) {
	b := []byte{9, 2, 0, 0, 2, 1, 0, 0x80, 50, 9, 4, 0, 0, 0, 2, 13, 0, 0, 5, 0x24, 0, 0x10, 1, 5, 0x24, 6, 0, 1, 13, 0x24, 15, 1, 0, 0, 0, 0, 0xea, 5, 0, 0, 0, 6, 0x24, 0x1a, 0, 1, 0, 9, 4, 1, 1, 2, 10, 0, 0, 0}
	le.PutUint16(b[2:], uint16(len(b)))
	f, e := ParseFunction(b, 0)
	if e != nil || f.Data != 1 || f.MaxSegment != 1514 {
		t.Fatal(f, e)
	}
	for i := range b {
		if _, e := ParseFunction(b[:i], 0); e == nil {
			t.Fatal("truncated descriptor accepted", i)
		}
	}
	p := make([]byte, 28)
	le.PutUint16(p, 28)
	le.PutUint16(p[2:], 1)
	le.PutUint32(p[4:], 16384)
	le.PutUint16(p[8:], 4)
	le.PutUint16(p[12:], 4)
	le.PutUint32(p[16:], 16384)
	le.PutUint16(p[20:], 4)
	le.PutUint16(p[24:], 4)
	if _, e := ParseParameters(p); e != nil {
		t.Fatal(e)
	}
	p[20] = 0
	if _, e := ParseParameters(p); e == nil {
		t.Fatal("zero divisor accepted")
	}
}
func FuzzDecode(f *testing.F) {
	b, _ := Encode([][]byte{make([]byte, 60)}, 1, params())
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b) })
}
