package ncm

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func referenceEncode(frames [][]byte, sequence uint16, p Parameters) ([]byte, error) {
	if len(frames) == 0 || (p.OutDatagrams != 0 && len(frames) > int(p.OutDatagrams)) {
		return nil, fmt.Errorf("invalid datagram count")
	}
	alignment, divisor, remainder := int(p.OutAlignment), int(p.OutDivisor), int(p.OutRemainder)
	if alignment < 4 || alignment&(alignment-1) != 0 || divisor < 1 || remainder >= divisor {
		return nil, fmt.Errorf("invalid output alignment")
	}
	ndp := (12 + alignment - 1) / alignment * alignment
	cursor := ndp + 8 + 4*(len(frames)+1)
	offsets := make([]int, len(frames))
	for i, f := range frames {
		if len(f) < 14 || len(f) > 65535 {
			return nil, fmt.Errorf("invalid Ethernet length")
		}
		// NCM payload begins after the 14-byte Ethernet header.
		cursor += (remainder - (cursor+14)%divisor + divisor) % divisor
		offsets[i] = cursor
		cursor += len(f)
	}
	limit := min(uint32(MaxNTB), p.OutMax)
	if cursor > int(limit) {
		return nil, fmt.Errorf("NTB length %d exceeds %d", cursor, limit)
	}
	b := make([]byte, cursor)
	copy(b, "NCMH")
	le.PutUint16(b[4:], 12)
	le.PutUint16(b[6:], sequence)
	le.PutUint16(b[8:], uint16(cursor))
	le.PutUint16(b[10:], uint16(ndp))
	copy(b[ndp:], "NCM0")
	le.PutUint16(b[ndp+4:], uint16(8+4*(len(frames)+1)))
	for i, f := range frames {
		le.PutUint16(b[ndp+8+4*i:], uint16(offsets[i]))
		le.PutUint16(b[ndp+10+4*i:], uint16(len(f)))
		copy(b[offsets[i]:], f)
	}
	return b, nil
}

func TestEncodeIntoMatchesOriginalDirtyBuffer(t *testing.T) {
	rng := rand.New(rand.NewSource(18))
	buffer := bytes.Repeat([]byte{0xa5}, MaxNTB)
	for iteration := 0; iteration < 800; iteration++ {
		p := params()
		p.OutMax = uint32(64 + rng.Intn(MaxNTB-64))
		p.OutAlignment = uint16(4 << rng.Intn(5))
		p.OutDivisor = uint16(1 << rng.Intn(6))
		p.OutRemainder = uint16(rng.Intn(int(p.OutDivisor)))
		if iteration%3 == 0 {
			p.OutDatagrams = uint16(1 + rng.Intn(40))
		}
		frames := make([][]byte, 1+rng.Intn(40))
		for i := range frames {
			frames[i] = make([]byte, 14+rng.Intn(1501))
			rng.Read(frames[i])
		}
		sequence := uint16(rng.Int())
		want, we := referenceEncode(frames, sequence, p)
		got, ge := EncodeInto(buffer, frames, sequence, p)
		if (we == nil) != (ge == nil) || (we == nil && !bytes.Equal(want, got)) {
			t.Fatalf("mismatch %d: %v/%v", iteration, we, ge)
		}
		if ge == nil {
			if _, e := Decode(got); e != nil {
				t.Fatal(e)
			}
		}
	}
}
func TestStreamDoesNotAliasInputOrLaterFeeds(t *testing.T) {
	frame := bytes.Repeat([]byte{0x42}, 1500)
	first, _ := Encode([][]byte{frame}, 1, params())
	second, _ := Encode([][]byte{bytes.Repeat([]byte{0x83}, 1500)}, 2, params())
	for cut := 0; cut <= len(second); cut++ {
		stream := Stream{}
		input := append(append([]byte(nil), first...), second[:cut]...)
		blocks, e := stream.Feed(input)
		if e != nil {
			t.Fatal(e)
		}
		clear(input)
		tail, e := stream.Feed(second[cut:])
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 20; i++ {
			if _, e = stream.Feed(first); e != nil {
				t.Fatal(e)
			}
		}
		if len(blocks) == 0 || !bytes.Equal(blocks[0].Frames[0], frame) {
			t.Fatalf("old block corrupted at %d", cut)
		}
		if len(blocks)+len(tail) != 2 || len(stream.Pending) != 0 {
			t.Fatalf("fragment handling %d", cut)
		}
	}
}
func TestEncodeIntoZeroAllocationsWithReadyStorage(t *testing.T) {
	p := params()
	p.OutMax = 65535
	frames := make([][]byte, 16)
	for i := range frames {
		frames[i] = make([]byte, 1514)
	}
	buf := make([]byte, MaxNTB)
	if n := testing.AllocsPerRun(100, func() {
		if _, e := EncodeInto(buf, frames, 1, p); e != nil {
			panic(e)
		}
	}); n != 0 {
		t.Fatalf("hot encoder allocations=%v", n)
	}
}
func BenchmarkEncodeReuse(b *testing.B) {
	p := params()
	p.OutMax = 65535
	frames := make([][]byte, 16)
	for i := range frames {
		frames[i] = make([]byte, 1514)
	}
	for _, reuse := range []bool{false, true} {
		b.Run(fmt.Sprint(reuse), func(b *testing.B) {
			buf := make([]byte, MaxNTB)
			b.ReportAllocs()
			b.SetBytes(16 * 1514)
			for i := 0; i < b.N; i++ {
				var e error
				if reuse {
					_, e = EncodeInto(buf, frames, uint16(i), p)
				} else {
					_, e = referenceEncode(frames, uint16(i), p)
				}
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
