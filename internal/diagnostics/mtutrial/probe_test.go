package mtutrial

import (
	"encoding/binary"
	"suhang/usbnet/internal/transport/ncm"
	"testing"
	"time"
)

var testMAC = [6]byte{2, 3, 4, 5, 6, 7}

func reply(f []byte) []byte {
	b := append([]byte(nil), f...)
	copy(b[:6], f[6:12])
	copy(b[6:12], f[:6])
	ip := b[14:]
	src := append([]byte(nil), ip[12:16]...)
	copy(ip[12:16], ip[16:20])
	copy(ip[16:20], src)
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:], ncm.Checksum(ip[:20]))
	c := ip[20:]
	c[0] = 0
	c[2], c[3] = 0, 0
	binary.BigEndian.PutUint16(c[2:], ncm.Checksum(c))
	return b
}
func TestJumboProofRequiresTwoUnfragmentedFreshReplies(t *testing.T) {
	tr := New(testMAC, [16]byte{1, 2, 3}, 16014)
	now := time.Now()
	first := tr.Tick(now)
	if len(first) != 9014 {
		t.Fatal(len(first))
	}
	good := reply(first)
	for _, mutate := range []func([]byte){
		func(b []byte) { b[6] ^= 1 }, func(b []byte) { b[0] ^= 1 }, func(b []byte) { b[len(b)-1] ^= 1 },
		func(b []byte) {
			ip := b[14:]
			binary.BigEndian.PutUint16(ip[6:], 0x2000)
			ip[10], ip[11] = 0, 0
			binary.BigEndian.PutUint16(ip[10:], ncm.Checksum(ip[:20]))
		},
	} {
		b := append([]byte(nil), good...)
		mutate(b)
		if _, ok := tr.Accept(b); ok {
			t.Fatal("untrusted proof accepted")
		}
	}
	if v, ok := tr.Accept(good); !ok || v != 0 || tr.Proven != 1500 {
		t.Fatal("premature upgrade")
	}
	if _, ok := tr.Accept(good); ok {
		t.Fatal("replay accepted")
	}
	second := tr.Tick(now.Add(time.Second))
	if v, ok := tr.Accept(reply(second)); !ok || v != 9000 || tr.Done {
		t.Fatal("9000 proof missing")
	}
	if _, ok := tr.Accept(good); ok {
		t.Fatal("previous stage accepted")
	}
	for i := 0; i < 2; i++ {
		f := tr.Tick(now.Add(time.Duration(i+2) * time.Second))
		if len(f) != 16014 {
			t.Fatal(len(f))
		}
		tr.Accept(reply(f))
	}
	if !tr.Done || tr.Proven != 16000 {
		t.Fatal(tr)
	}
}
func TestTimeoutPreservesBaselineOrLowerProvenMTU(t *testing.T) {
	for _, proveLower := range []bool{false, true} {
		tr := New(testMAC, [16]byte{1}, 16014)
		now := time.Now()
		for i := 0; i < 12; i++ {
			f := tr.Tick(now.Add(time.Duration(i) * time.Second))
			if proveLower && len(f) == 9014 {
				tr.Accept(reply(f))
			}
		}
		want := 1500
		if proveLower {
			want = 9000
		}
		if !tr.Done || tr.Proven != want {
			t.Fatal(tr)
		}
	}
	if tr := New(testMAC, [16]byte{}, 1514); !tr.Done || tr.Tick(time.Now()) != nil {
		t.Fatal("unsupported frame capacity")
	}
}
