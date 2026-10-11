package ipadncm

import (
	"bytes"
	"testing"
)

func TestAppleModeControlReply(t *testing.T) {
	// A driver's byte count includes the setup header, not just the payload.
	b := []byte{0xc0, 0x45, 0, 0, 0, 0, 4, 0, 3, 3, 3, 0}
	out := make([]byte, 4)
	n, e := appleModeReply(b[:8], b, 12, out)
	if e != nil || n != 4 || !bytes.Equal(out, []byte{3, 3, 3, 0}) {
		t.Fatalf("valid reply: %d %v %v", n, out, e)
	}
	for _, count := range []uint32{0, 7, 13, ^uint32(0)} {
		if _, e := appleModeReply(b[:8], b, count, out); e == nil {
			t.Fatalf("accepted invalid count %d", count)
		}
	}
	// A short transfer is valid framing but must not become a four-byte mode.
	if n, e := appleModeReply(b[:8], b, 8, out); e != nil || n != 0 {
		t.Fatalf("empty payload: %d %v", n, e)
	}
	bad := append([]byte(nil), b...)
	bad[1] = 0x52
	if _, e := appleModeReply(b[:8], bad, 12, out); e == nil {
		t.Fatal("accepted different request header")
	}
	if _, e := appleModeReply(b[:8], b, 12, out[:1]); e == nil {
		t.Fatal("accepted oversized payload")
	}
}

func TestAppleModeOperationAllowlist(t *testing.T) {
	read, e := appleModePacket(0xc0, 0x45, 0, 0, 4)
	if e != nil || !bytes.Equal(read[:8], []byte{0xc0, 0x45, 0, 0, 0, 0, 4, 0}) {
		t.Fatalf("GET_MODE: %v %v", read, e)
	}
	set, e := appleModePacket(0xc0, 0x52, 0, 3, 1)
	if e != nil || !bytes.Equal(set[:8], []byte{0xc0, 0x52, 0, 0, 3, 0, 1, 0}) {
		t.Fatalf("SET_MODE: %v %v", set, e)
	}
	for _, args := range [][5]int{{0x40, 0x52, 0, 3, 1}, {0xc0, 0x52, 1, 3, 1}, {0xc0, 0x52, 0, 4, 1}, {0xc0, 0x45, 0, 0, 3}, {0xc0, 0x44, 0, 0, 4}, {0xc0, 0x45, 0, 0, -1}} {
		if _, e := appleModePacket(byte(args[0]), byte(args[1]), uint16(args[2]), uint16(args[3]), args[4]); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
