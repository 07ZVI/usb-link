package main

import (
	"math"
	"testing"
)

func TestSummaryAndMemorySlope(t *testing.T) {
	if describe(nil) != nil {
		t.Fatal("no samples must not report zero resource use")
	}
	v := describe([]float64{3, 1, 2, 100})
	if v.Mean != 26.5 || v.P95 != 100 || v.Max != 100 {
		t.Fatal(v)
	}
	s := slope([]point{{0, 1 << 20}, {1800, 2 << 20}, {3600, 3 << 20}})
	if s == nil || math.Abs(*s-2) > 1e-9 {
		t.Fatal(s)
	}
	if slope([]point{{0, 10}, {0, 20}}) != nil {
		t.Fatal("zero elapsed time must not fabricate slope")
	}
}
