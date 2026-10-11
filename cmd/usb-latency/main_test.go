package main

import (
	"bytes"
	"testing"
)

func TestPacketAuthenticationAndQuantiles(t *testing.T) {
	c := credentials{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16)}
	b := packet(c, 117)
	seq, ok := authenticate(c, b)
	if !ok || seq != 117 || len(b) != 64 {
		t.Fatal(seq, ok)
	}
	b[40] ^= 1
	if _, ok = authenticate(c, b); ok {
		t.Fatal("unauthenticated echo accepted")
	}
	b = packet(c, 117)
	c.nonce[0] ^= 1
	if _, ok = authenticate(c, b); ok {
		t.Fatal("other test session accepted")
	}
	if _, ok = authenticate(c, b[:63]); ok {
		t.Fatal("short packet accepted")
	}
	p50, p99, max := summarize([]float64{4, 1, 3, 2})
	if *p50 != 2 || *p99 != 4 || *max != 4 {
		t.Fatal(p50, p99, max)
	}
	p50, _, _ = summarize(nil)
	if p50 != nil {
		t.Fatal("no replies must not report zero latency")
	}
}
