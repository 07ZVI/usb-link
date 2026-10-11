package ncm

import (
	"bytes"
	"suhang/usbnet/internal/transport/packetbuffer"
	"testing"
)

func TestPooledStreamHoldsCoalescedStorageUntilLastRelease(t *testing.T) {
	p := packetbuffer.New()
	f := bytes.Repeat([]byte{0x3a}, 16014)
	b, e := Encode([][]byte{f}, 7, Parameters{OutMax: 32764, OutAlignment: 4, OutDivisor: 4})
	if e != nil {
		t.Fatal(e)
	}
	joined := append(append([]byte(nil), b...), b...)
	s := Stream{Pool: p}
	defer s.Close()
	out, e := s.Feed(joined)
	if e != nil || len(out) != 2 {
		t.Fatal(e, len(out))
	}
	clear(joined)
	if !bytes.Equal(out[0].Frames[0], f) || !bytes.Equal(out[1].Frames[0], f) {
		t.Fatal("aliased native input")
	}
	out[0].Release()
	borrow := p.Get(len(b) * 2)
	clear(borrow)
	p.Put(borrow)
	if !bytes.Equal(out[1].Frames[0], f) {
		t.Fatal("released shared NTB before last consumer")
	}
	out[1].Release()
}
func TestPooledStreamMatchesLegacyAcrossPartialFeedsAndModeChanges(t *testing.T) {
	p := packetbuffer.New()
	var wire []byte
	for i := 0; i < 12; i++ {
		f := bytes.Repeat([]byte{byte(i + 1)}, 14+i*991)
		b, e := Encode([][]byte{f}, uint16(i), Parameters{OutMax: 32764, OutAlignment: 4, OutDivisor: 4})
		if e != nil {
			t.Fatal(e)
		}
		wire = append(wire, b...)
	}
	for _, split := range []int{1, 11, 13, 1514, 16384, 32764} {
		a := Stream{}
		b := Stream{Pool: p}
		var saved []Block
		for start, step := 0, 0; start < len(wire); step++ {
			end := min(start+split, len(wire))
			if step%3 == 0 {
				b.Pool = nil
			} else {
				b.Pool = p
			}
			want, we := a.Feed(wire[start:end])
			got, ge := b.Feed(wire[start:end])
			if (we != nil) != (ge != nil) || len(want) != len(got) {
				t.Fatal(split, start, we, ge)
			}
			for i := range want {
				if got[i].Sequence != want[i].Sequence || len(got[i].Frames) != len(want[i].Frames) {
					t.Fatal("headers changed")
				}
				for j := range want[i].Frames {
					if !bytes.Equal(got[i].Frames[j], want[i].Frames[j]) {
						t.Fatal("frames changed")
					}
				}
			}
			saved = append(saved, got...)
			start = end
		}
		for _, block := range saved {
			for _, f := range block.Frames {
				if f[0] != byte(block.Sequence+1) {
					t.Fatal("later feed overwrote held block")
				}
			}
			block.Release()
		}
		b.Close()
	}
}
func TestPooledStreamRejectsSameMalformedData(t *testing.T) {
	for _, wire := range [][]byte{bytes.Repeat([]byte{1}, 20), []byte("NCMHxxxx\x01\x00xx"), make([]byte, 131073)} {
		a := Stream{}
		b := Stream{Pool: packetbuffer.New()}
		_, we := a.Feed(wire)
		_, ge := b.Feed(wire)
		if we == nil || ge == nil || we.Error() != ge.Error() {
			t.Fatal(we, ge)
		}
		b.Close()
	}
}
