package main

import "testing"

func TestCPUWindowsUseActualDurationAndExcludePartial(t *testing.T) {
	var s series
	for i := 0; i < 59; i++ {
		s.add(sample{Interval: 1, CPU: 1.5625})
	}
	if len(s.WindowCPU) != 0 {
		t.Fatal("partial window reported")
	}
	s.add(sample{Interval: 1.5, CPU: 0})
	if len(s.WindowCPU) != 1 || s.WindowCPU[0] != 59*1.5625/60.5 {
		t.Fatal(s.WindowCPU)
	}
	s.add(sample{Interval: 1, CPU: 100})
	if len(s.WindowCPU) != 1 || s.WindowSeconds != 1 {
		t.Fatal("trailing window counted as complete")
	}
}
