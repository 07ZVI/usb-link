//go:build windows && amd64

// Package memorydiag reads region metadata only; it never reads memory contents,
// suspends threads, walks live heaps or trims another component's allocations.
package memorydiag

import (
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

type regionInfo struct {
	Base, Allocation        uintptr
	AllocationProtection    uint32
	Padding                 uint32
	Size                    uintptr
	State, Protection, Kind uint32
	Tail                    uint32
}

var _ [48 - unsafe.Sizeof(regionInfo{})]byte
var _ [unsafe.Sizeof(regionInfo{}) - 48]byte
var kernel = windows.NewLazySystemDLL("kernel32.dll")
var query = kernel.NewProc("VirtualQuery")
var heaps = kernel.NewProc("GetProcessHeaps")

func Snapshot() any {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	out := map[string]any{"go": mem, "startup_stages": StartupStages(), "coverage": "VirtualQuery metadata; native heap root regions only; no allocation-owner or stack attribution; startup increments include concurrent activity"}
	var heapIDs [1024]uintptr
	n, _, e := heaps.Call(1024, uintptr(unsafe.Pointer(&heapIDs[0])))
	if n == 0 || n > 1024 {
		out["heap_error"] = fmt.Sprint(e)
		n = 0
	}
	roots := make(map[uintptr]bool)
	for _, h := range heapIDs[:int(n)] {
		roots[h] = true
	}
	totals := map[string]uint64{"private_commit": 0, "mapped_commit": 0, "image_commit": 0, "native_heap_root_commit": 0}
	regions := 0
	var address uintptr
	for address < 0x0000800000000000 && regions < 262144 {
		var r regionInfo
		got, _, _ := query.Call(address, uintptr(unsafe.Pointer(&r)), 48)
		if got != 48 || r.Size == 0 || r.Base+r.Size <= address {
			break
		}
		regions++
		if r.State == 0x1000 {
			switch r.Kind {
			case 0x20000:
				totals["private_commit"] += uint64(r.Size)
			case 0x40000:
				totals["mapped_commit"] += uint64(r.Size)
			case 0x1000000:
				totals["image_commit"] += uint64(r.Size)
			}
			if roots[r.Allocation] {
				totals["native_heap_root_commit"] += uint64(r.Size)
			}
		}
		address = r.Base + r.Size
	}
	out["regions"] = regions
	out["native_heap_roots"] = n
	out["regions_commit_bytes"] = totals
	return out
}
