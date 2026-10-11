package ncm

import (
	"math/rand"
	"testing"
)

func TestJumboBatchesFitAndPreserveSmallBatch(t *testing.T) {
	p := Parameters{InMax: 32764, OutMax: 32764, OutDivisor: 4, OutAlignment: 4, OutDatagrams: 512}
	b, e := NewBatchSizes(p, 16, 16014)
	if e != nil {
		t.Fatal(e)
	}
	for _, size := range []int{1514, 9014, 16014} {
		frames := make([][]byte, 16)
		for i := range frames {
			frames[i] = make([]byte, size)
		}
		n, e := b.Limit(frames)
		if e != nil {
			t.Fatal(e)
		}
		if size == 1514 && n != 16 {
			t.Fatal(n)
		}
		for len(frames) > 0 {
			count, e := b.Limit(frames)
			if e != nil {
				t.Fatal(e)
			}
			block, e := Encode(frames[:count], 0, p)
			if e != nil || len(block) > 32764 {
				t.Fatal(len(block), e)
			}
			frames = frames[count:]
		}
	}
	if _, e = b.Limit([][]byte{make([]byte, 16015)}); e == nil {
		t.Fatal("oversize allowed")
	}
}

func TestActualSizePackingOfShortTailsAndMixedFrames(t *testing.T) {
	p := Parameters{OutMax: 32764, OutDivisor: 4, OutAlignment: 4, OutDatagrams: 512}
	b, err := NewBatchSizes(p, 16, 16014)
	if err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{make([]byte, 16014)}
	for i := 0; i < 15; i++ {
		frames = append(frames, make([]byte, 1514))
	}
	n, err := b.Limit(frames)
	if err != nil || n != 12 {
		t.Fatalf("mixed count=%d error=%v", n, err)
	}
	for i := range frames {
		frames[i] = make([]byte, 2014)
	}
	n, err = b.Limit(frames)
	if err != nil || n != 16 {
		t.Fatalf("short tail count=%d error=%v", n, err)
	}
}

// The production encoder is an independent oracle for exact bounds and FIFO
// contents, including non-default divisor/remainder/alignment combinations.
func TestActualPrefixMatchesEncoder(t *testing.T) {
	r := rand.New(rand.NewSource(825))
	for trial := 0; trial < 2000; trial++ {
		divisor := uint16(1 + r.Intn(16))
		p := Parameters{OutMax: uint32(17000 + r.Intn(16000)), OutDivisor: divisor,
			OutRemainder: uint16(r.Intn(int(divisor))), OutAlignment: uint16(4 << r.Intn(4)), OutDatagrams: uint16(1 + r.Intn(32))}
		requested := 1 + r.Intn(32)
		b, err := NewBatchSizes(p, requested, 16014)
		if err != nil {
			t.Fatal(err)
		}
		frames := make([][]byte, 1+r.Intn(32))
		for i := range frames {
			frames[i] = make([]byte, 14+r.Intn(16001))
			frames[i][0] = byte(i)
		}
		for len(frames) > 0 {
			n, err := b.Limit(frames)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			for count := 1; count <= min(requested, len(frames)); count++ {
				if _, err := Encode(frames[:count], 0, p); err != nil {
					break
				}
				want = count
			}
			if n != want {
				t.Fatalf("trial %d: prefix=%d encoder=%d", trial, n, want)
			}
			encoded, err := Encode(frames[:n], 0, p)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(encoded)
			if err != nil || len(decoded.Frames) != n {
				t.Fatal(err)
			}
			for i, f := range decoded.Frames {
				if f[0] != frames[i][0] {
					t.Fatal("FIFO changed")
				}
			}
			frames = frames[n:]
		}
	}
}

func BenchmarkActualPrefix(b *testing.B) {
	p := Parameters{OutMax: 32764, OutDivisor: 4, OutAlignment: 4, OutDatagrams: 512}
	batch, _ := NewBatchSizes(p, 16, 16014)
	frames := make([][]byte, 16)
	for i := range frames {
		frames[i] = make([]byte, 1514)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := batch.Limit(frames); err != nil {
			b.Fatal(err)
		}
	}
}
