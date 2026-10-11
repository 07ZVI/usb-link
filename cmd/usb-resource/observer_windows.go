//go:build windows && amd64

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var snapshotProc = kernel.NewProc("CreateToolhelp32Snapshot")
var firstProc = kernel.NewProc("Process32FirstW")
var nextProc = kernel.NewProc("Process32NextW")
var openProc = kernel.NewProc("OpenProcess")
var timesProc = kernel.NewProc("GetProcessTimes")
var memoryProc = kernel.NewProc("K32GetProcessMemoryInfo")
var handlesProc = kernel.NewProc("GetProcessHandleCount")
var waitProc = kernel.NewProc("WaitForSingleObject")
var imageProc = kernel.NewProc("QueryFullProcessImageNameW")
var nowProc = kernel.NewProc("GetSystemTimeAsFileTime")

type processEntry struct {
	Size, Usage, PID        uint32
	Heap                    uintptr
	Module, Threads, Parent uint32
	Priority                int32
	Flags                   uint32
	Name                    [260]uint16
}
type filetime struct{ Low, High uint32 }

func (f filetime) value() uint64 { return uint64(f.High)<<32 | uint64(f.Low) }

type memoryCounters struct {
	Size, PageFaults                                                                                uint32
	PeakWorking, Working, PeakPaged, Paged, PeakNonPaged, NonPaged, Pagefile, PeakPagefile, Private uintptr
}
type tracked struct {
	Handle     syscall.Handle
	Base, Last uint64
	Row        processSample
	Initial    bool
	Samples    int
	Data       series
	Done       bool
}
type observer struct {
	Root            uint32
	All             map[uint32]*tracked
	Retired         []*tracked
	RootCreated     uint64
	Scheduler       *scheduler
	StartedFiletime uint64
	Observer        *tracked
}

func newObserver(root uint32) (*observer, error) {
	p, e := openTracked(uint32(os.Getpid()), processEntry{}, true)
	if e != nil {
		return nil, e
	}
	var ft filetime
	nowProc.Call(uintptr(unsafe.Pointer(&ft)))
	return &observer{Root: root, All: map[uint32]*tracked{}, Observer: p, Scheduler: newScheduler(), StartedFiletime: ft.value()}, nil
}
func (o *observer) close() {
	for _, p := range o.All {
		syscall.CloseHandle(p.Handle)
	}
	syscall.CloseHandle(o.Observer.Handle)
	o.Scheduler.close()
}
func cpu(h syscall.Handle) (uint64, uint64, error) {
	var c, e, k, u filetime
	r, _, err := timesProc.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(unsafe.Pointer(&e)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	if r == 0 {
		return 0, 0, err
	}
	return c.value(), k.value() + u.value(), nil
}
func openTracked(pid uint32, v processEntry, initial bool) (*tracked, error) {
	r, _, e := openProc.Call(0x1000|0x100000, 0, uintptr(pid))
	if r == 0 {
		return nil, e
	}
	h := syscall.Handle(r)
	var path [32768]uint16
	size := uint32(len(path))
	ok, _, imageError := imageProc.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		syscall.CloseHandle(h)
		return nil, imageError
	}
	if size > uint32(len(path)) {
		syscall.CloseHandle(h)
		return nil, fmt.Errorf("process image length out of bounds")
	}
	name := filepath.Base(syscall.UTF16ToString(path[:size]))
	expected := syscall.UTF16ToString(v.Name[:])
	if expected != "" && !strings.EqualFold(name, expected) {
		syscall.CloseHandle(h)
		return nil, fmt.Errorf("snapshot/image generation mismatch")
	}
	created, t, e := cpu(h)
	if e != nil {
		syscall.CloseHandle(h)
		return nil, e
	}
	base := t
	if !initial {
		base = 0
	}
	return &tracked{Handle: h, Base: base, Last: base, Initial: initial, Row: processSample{PID: pid, ParentPID: v.Parent, Name: name, Created: created, Threads: v.Threads}}, nil
}
func processList() (map[uint32]processEntry, error) {
	if rows, e := batchedProcessList(); e == nil {
		enumerationBackend = "batched native process snapshot"
		return rows, nil
	}
	enumerationBackend = "Toolhelp fallback; observer overhead must be assessed"
	return toolhelpProcessList()
}
func toolhelpProcessList() (map[uint32]processEntry, error) {
	r, _, e := snapshotProc.Call(2, 0)
	if r == ^uintptr(0) {
		return nil, e
	}
	h := syscall.Handle(r)
	defer syscall.CloseHandle(h)
	v := processEntry{Size: uint32(unsafe.Sizeof(processEntry{}))}
	ok, _, e := firstProc.Call(r, uintptr(unsafe.Pointer(&v)))
	if ok == 0 {
		return nil, e
	}
	out := map[uint32]processEntry{}
	for {
		out[v.PID] = v
		ok, _, e = nextProc.Call(r, uintptr(unsafe.Pointer(&v)))
		if ok == 0 {
			if e != syscall.Errno(18) {
				return nil, e
			}
			break
		}
	}
	return out, nil
}
func product(v processEntry) bool {
	switch strings.ToLower(syscall.UTF16ToString(v.Name[:])) {
	case "usb-link.exe", "ipad-usb-easy.exe", "suhang-usbnet.exe", "usblink.desktop.exe":
		return true
	}
	return false
}
func (p *tracked) read(dt float64, threads uint32) (processSample, error) {
	r := p.Row
	r.Threads = threads
	created, t, e := cpu(p.Handle)
	if e != nil {
		return r, e
	}
	if created != r.Created || t < p.Last {
		return r, fmt.Errorf("process identity/time changed")
	}
	r.CPUSeconds = float64(t) / 1e7
	if dt > 0 {
		r.CPUPercent = float64(t-p.Last) / 1e7 / dt * 100
	}
	p.Last = t
	wait, _, err := waitProc.Call(uintptr(p.Handle), 0)
	if wait == 0 {
		r.Exited = true
		r.Threads = 0
		p.Done = true
		return r, nil
	}
	if wait != 258 {
		return r, fmt.Errorf("process exit query: %v", err)
	}
	mem := memoryCounters{Size: uint32(unsafe.Sizeof(memoryCounters{}))}
	ok, _, err := memoryProc.Call(uintptr(p.Handle), uintptr(unsafe.Pointer(&mem)), uintptr(mem.Size))
	if ok == 0 {
		return r, fmt.Errorf("memory query: %v", err)
	}
	r.PrivateBytes = uint64(mem.Private)
	r.WorkingSet = uint64(mem.Working)
	ok, _, err = handlesProc.Call(uintptr(p.Handle), uintptr(unsafe.Pointer(&r.Handles)))
	if ok == 0 {
		return r, fmt.Errorf("handle query: %v", err)
	}
	return r, nil
}
func (o *observer) capture(elapsed, dt float64) (sample, error) {
	all, e := processList()
	if e != nil {
		return sample{}, e
	}
	r := sample{Elapsed: elapsed, Interval: dt}
	// Retained handles refer to the old process even when Windows reuses its PID.
	// Finish its CPU accounting and retire it before discovering a replacement.
	for pid, p := range o.All {
		wait, _, _ := waitProc.Call(uintptr(p.Handle), 0)
		if wait != 0 {
			continue
		}
		row, err := p.read(dt, 0)
		if err != nil {
			row.Error = err.Error()
			r.Errors = append(r.Errors, fmt.Sprintf("pid %d final CPU: %v", pid, err))
		}
		r.Processes = append(r.Processes, row)
		r.CPU += row.CPUPercent
		p.Done = true
		syscall.CloseHandle(p.Handle)
		p.Handle = 0
		o.Retired = append(o.Retired, p)
		delete(o.All, pid)
	}
	selected := map[uint32]bool{}
	for pid, v := range all {
		if pid == uint32(os.Getpid()) {
			continue
		}
		if (o.Root == 0 && product(v)) || (pid == o.Root && product(v) && (o.RootCreated == 0 || o.All[pid] != nil)) {
			selected[pid] = true
		}
	}
	// Descendants are admitted only while their parent's retained identity still exists.
	for pid, p := range o.All {
		if !p.Done {
			selected[pid] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for pid, v := range all {
			if !selected[pid] && selected[v.Parent] && pid != uint32(os.Getpid()) {
				selected[pid] = true
				changed = true
			}
		}
	}
	ids := make([]uint32, 0, len(selected))
	for pid := range selected {
		ids = append(ids, pid)
	}
	depth := func(pid uint32) int {
		seen := map[uint32]bool{}
		n := 0
		for n < 64 && !seen[pid] {
			seen[pid] = true
			v, ok := all[pid]
			if !ok || !selected[v.Parent] {
				break
			}
			pid = v.Parent
			n++
		}
		return n
	}
	sort.Slice(ids, func(i, j int) bool {
		di, dj := depth(ids[i]), depth(ids[j])
		if di == dj {
			return ids[i] < ids[j]
		}
		return di < dj
	})
	for _, pid := range ids {
		v, exists := all[pid]
		p := o.All[pid]
		if p == nil {
			if !exists {
				continue
			}
			p, e = openTracked(pid, v, elapsed == 0)
			if e != nil {
				r.Errors = append(r.Errors, fmt.Sprintf("pid %d open: %v", pid, e))
				continue
			}
			if p.Row.Created <= o.StartedFiletime && !p.Initial {
				p.Initial = true
				_, t, err := cpu(p.Handle)
				if err != nil {
					syscall.CloseHandle(p.Handle)
					r.Errors = append(r.Errors, "late preexisting process CPU unavailable")
					continue
				}
				p.Base = t
				p.Last = t
				r.Errors = append(r.Errors, fmt.Sprintf("pid %d existed before capture but was discovered late; early CPU unmeasured", pid))
			}
			if pid == o.Root {
				if o.RootCreated != 0 && o.RootCreated != p.Row.Created {
					syscall.CloseHandle(p.Handle)
					r.Errors = append(r.Errors, "requested root PID was reused; replacement excluded")
					continue
				}
				o.RootCreated = p.Row.Created
			}
			if !product(v) {
				parent := o.All[v.Parent]
				if parent == nil || p.Row.Created < parent.Row.Created {
					syscall.CloseHandle(p.Handle)
					r.Errors = append(r.Errors, fmt.Sprintf("pid %d parent generation unconfirmed; excluded", pid))
					continue
				}
			}
			if len(o.Retired)+len(o.All) >= 4096 {
				syscall.CloseHandle(p.Handle)
				r.Errors = append(r.Errors, "process lifetime limit reached; coverage incomplete")
				continue
			}
			o.All[pid] = p
		}
		if p.Done {
			continue
		}
		row, err := p.read(dt, v.Threads)
		if err != nil {
			row.Error = err.Error()
			r.Errors = append(r.Errors, fmt.Sprintf("pid %d: %v", pid, err))
		}
		r.Processes = append(r.Processes, row)
		r.CPU += row.CPUPercent
		if !row.Exited {
			r.Private += row.PrivateBytes
			r.Working += row.WorkingSet
			r.Handles += uint64(row.Handles)
			r.Threads += uint64(row.Threads)
		}
		p.Samples++
		if !row.Exited && err == nil {
			p.Data.add(sample{Elapsed: elapsed, Interval: dt, CPU: row.CPUPercent, Private: row.PrivateBytes, Working: row.WorkingSet, Handles: uint64(row.Handles), Threads: uint64(row.Threads)})
		}
	}
	if len(r.Processes) == 0 {
		r.Errors = append(r.Errors, "no product process found; absence is not an idle baseline")
	}
	r.ThreadSamples, e = o.Scheduler.sample(o.All)
	if e != nil {
		r.Errors = append(r.Errors, "scheduler counters incomplete: "+e.Error())
	} else if dt > 0 && len(r.ThreadSamples) > 0 {
		var total float64
		for _, t := range r.ThreadSamples {
			total += t.Switches
		}
		r.Switches = &total
	}
	sort.Slice(r.Processes, func(i, j int) bool { return r.Processes[i].PID < r.Processes[j].PID })
	r.Observer, e = o.Observer.read(dt, all[uint32(os.Getpid())].Threads)
	if e != nil {
		r.Errors = append(r.Errors, "observer query: "+e.Error())
	}
	return r, nil
}
func (o *observer) lifetimes() any {
	out := []any{}
	all := append([]*tracked(nil), o.Retired...)
	for _, p := range o.All {
		all = append(all, p)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Row.Created < all[j].Row.Created })
	for _, p := range all {
		out = append(out, map[string]any{"pid": p.Row.PID, "parent_pid": p.Row.ParentPID, "name": p.Row.Name, "creation_filetime": p.Row.Created, "present_at_start": p.Initial, "observed_cpu_seconds": float64(p.Last-p.Base) / 1e7, "exited": p.Done, "samples": p.Samples, "metrics": p.Data.summary()})
	}
	return out
}
func (o *observer) starts() any {
	all := append([]*tracked(nil), o.Retired...)
	for _, p := range o.All {
		all = append(all, p)
	}
	byName := map[string]map[string]any{}
	var starts uint64
	for _, p := range all {
		if p.Initial {
			continue
		}
		starts++
		name := strings.ToLower(p.Row.Name)
		v := byName[name]
		if v == nil {
			v = map[string]any{"observed_starts_lower_bound": uint64(0), "known_cpu_seconds_since_capture": float64(0)}
			byName[name] = v
		}
		v["observed_starts_lower_bound"] = v["observed_starts_lower_bound"].(uint64) + 1
		v["known_cpu_seconds_since_capture"] = v["known_cpu_seconds_since_capture"].(float64) + float64(p.Last-p.Base)/1e7
	}
	return map[string]any{"observed_new_processes_lower_bound": starts, "by_name": byName, "complete": false}
}
