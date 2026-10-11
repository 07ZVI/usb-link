//go:build windows && amd64

package bridgeworker

import (
	"golang.org/x/sys/windows"
	"runtime"
	"suhang/usbnet/internal/diagnostics/bench"
)

type performanceCounters struct {
	WinUSBCached     bool    `json:"winusb_cached"`
	BuffersReused    bool    `json:"buffers_reused"`
	HeapAllocated    uint64  `json:"heap_allocated"`
	HeapInUse        uint64  `json:"heap_in_use"`
	HeapSystem       uint64  `json:"heap_system"`
	GCPreset         string  `json:"gc_preset"`
	GCPercent        int     `json:"gc_percent"`
	MemoryLimit      int64   `json:"memory_limit"`
	AllocatedBytes   uint64  `json:"allocated_bytes"`
	Allocations      uint64  `json:"allocations"`
	GCCycles         uint32  `json:"gc_cycles"`
	GCPauseNanos     uint64  `json:"gc_pause_nanos"`
	KernelCPUSeconds float64 `json:"kernel_cpu_seconds"`
	UserCPUSeconds   float64 `json:"user_cpu_seconds"`
	CPUError         string  `json:"cpu_error,omitempty"`
}

// Collected only for an explicit diagnostic request, never for ordinary packets.
func performanceSnapshot() performanceCounters {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	p := performanceCounters{AllocatedBytes: mem.TotalAlloc, Allocations: mem.Mallocs, GCCycles: mem.NumGC, GCPauseNanos: mem.PauseTotalNs}
	p.BuffersReused = bench.ReuseBuffers()
	p.WinUSBCached = bench.CachedWinUSB()
	p.HeapAllocated, p.HeapInUse, p.HeapSystem = mem.HeapAlloc, mem.HeapInuse, mem.HeapSys
	p.GCPreset, p.GCPercent, p.MemoryLimit = bench.GCSettings()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		p.CPUError = err.Error()
		return p
	}
	seconds := func(t windows.Filetime) float64 {
		return float64(uint64(t.HighDateTime)<<32|uint64(t.LowDateTime)) / 1e7
	}
	p.KernelCPUSeconds, p.UserCPUSeconds = seconds(kernel), seconds(user)
	return p
}
