//go:build windows && amd64

package memorydiag

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

type processCounters struct {
	Size, PageFaults                                                                                      uint32
	PeakWorkingSet, WorkingSet, PeakPaged, Paged, PeakNonPaged, NonPaged, Pagefile, PeakPagefile, Private uintptr
}

var _ [80 - unsafe.Sizeof(processCounters{})]byte
var _ [unsafe.Sizeof(processCounters{}) - 80]byte
var processMemory = kernel.NewProc("K32GetProcessMemoryInfo")
var stages struct {
	sync.Mutex
	Started time.Time
	Rows    []Stage
}

type Stage struct {
	Name       string           `json:"stage"`
	ElapsedNS  int64            `json:"elapsed_ns"`
	Private    uint64           `json:"private_bytes"`
	WorkingSet uint64           `json:"working_set_bytes"`
	Go         runtime.MemStats `json:"go"`
	Error      string           `json:"error,omitempty"`
}

func init() {
	stages.Started = time.Now()
	RecordStage("package_initialization")
	time.AfterFunc(120*time.Second, func() { RecordStage("natural_idle_after_120s") })
}

// Startup only: fixed names and a bounded history, no periodic sampling.
func RecordStage(name string) {
	stages.Lock()
	for _, r := range stages.Rows {
		if r.Name == name {
			stages.Unlock()
			return
		}
	}
	if len(stages.Rows) >= 128 {
		stages.Unlock()
		return
	}
	stages.Unlock()
	var r Stage
	r.Name = name
	r.ElapsedNS = time.Since(stages.Started).Nanoseconds()
	runtime.ReadMemStats(&r.Go)
	var p processCounters
	p.Size = 80
	ok, _, err := processMemory.Call(^uintptr(0), uintptr(unsafe.Pointer(&p)), 80)
	if ok == 0 {
		r.Error = fmt.Sprint(err)
	} else {
		r.Private = uint64(p.Private)
		r.WorkingSet = uint64(p.WorkingSet)
	}
	stages.Lock()
	defer stages.Unlock()
	if len(stages.Rows) < 128 {
		stages.Rows = append(stages.Rows, r)
	}
}
func StartupStages() []Stage {
	stages.Lock()
	defer stages.Unlock()
	return append([]Stage(nil), stages.Rows...)
}
