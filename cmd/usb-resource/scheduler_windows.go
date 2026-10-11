//go:build windows && amd64

package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var pdh = syscall.NewLazyDLL("pdh.dll")
var pdhOpen = pdh.NewProc("PdhOpenQueryW")
var pdhAdd = pdh.NewProc("PdhAddEnglishCounterW")
var pdhCollect = pdh.NewProc("PdhCollectQueryData")
var pdhArray = pdh.NewProc("PdhGetFormattedCounterArrayW")
var pdhClose = pdh.NewProc("PdhCloseQuery")

type scheduler struct {
	query, pids, tids, switches, cpu uintptr
	Err                              error
	primed                           bool
}

func newScheduler() *scheduler {
	s := &scheduler{}
	if !threadCountersEnabled {
		return s
	}
	code, _, _ := pdhOpen.Call(0, 0, uintptr(unsafe.Pointer(&s.query)))
	if code != 0 {
		s.Err = fmt.Errorf("PDH open 0x%x", code)
		return s
	}
	for _, a := range []struct {
		path string
		ptr  *uintptr
	}{{`\Thread(*)\ID Process`, &s.pids}, {`\Thread(*)\ID Thread`, &s.tids}, {`\Thread(*)\Context Switches/sec`, &s.switches}, {`\Thread(*)\% Processor Time`, &s.cpu}} {
		p, _ := syscall.UTF16PtrFromString(a.path)
		code, _, _ = pdhAdd.Call(s.query, uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(a.ptr)))
		if code != 0 {
			s.Err = fmt.Errorf("PDH add 0x%x", code)
			break
		}
	}
	return s
}
func (s *scheduler) close() {
	if s.query != 0 {
		pdhClose.Call(s.query)
	}
}
func pdhValues(counter uintptr) (map[string]float64, error) {
	var size, count uint32
	code, _, _ := pdhArray.Call(counter, 0x200|0x8000, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	if code != 0x800007d2 {
		return nil, fmt.Errorf("PDH sizing 0x%x", code)
	}
	if size < 24 || size > 16<<20 {
		return nil, fmt.Errorf("PDH size out of bounds")
	}
	b := make([]byte, size)
	code, _, _ = pdhArray.Call(counter, 0x200|0x8000, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&b[0])))
	if code != 0 {
		return nil, fmt.Errorf("PDH array 0x%x", code)
	}
	if uint64(count)*24 > uint64(len(b)) {
		return nil, fmt.Errorf("PDH count out of bounds")
	}
	base := uint64(uintptr(unsafe.Pointer(&b[0])))
	defer runtime.KeepAlive(b)
	out := map[string]float64{}
	for i := uint32(0); i < count; i++ {
		off := int(i) * 24
		status := binary.LittleEndian.Uint32(b[off+8:])
		if status > 1 {
			continue
		}
		addr := binary.LittleEndian.Uint64(b[off:])
		if addr < base || addr-base >= uint64(len(b)) {
			return nil, fmt.Errorf("PDH name pointer out of bounds")
		}
		pos := int(addr - base)
		name := []uint16{}
		ended := false
		for j := 0; j < 512 && pos+2 <= len(b); j++ {
			v := binary.LittleEndian.Uint16(b[pos:])
			pos += 2
			if v == 0 {
				ended = true
				break
			}
			name = append(name, v)
		}
		if !ended {
			return nil, fmt.Errorf("PDH name not terminated")
		}
		v := math.Float64frombits(binary.LittleEndian.Uint64(b[off+16:]))
		if !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 {
			out[string(utf16.Decode(name))] = v
		}
	}
	return out, nil
}
func (s *scheduler) sample(selected map[uint32]*tracked) ([]threadSample, error) {
	if s.query == 0 && s.Err == nil {
		return nil, nil
	}
	if s.Err != nil {
		return nil, s.Err
	}
	code, _, _ := pdhCollect.Call(s.query)
	if code != 0 {
		return nil, fmt.Errorf("PDH collect 0x%x", code)
	}
	if !s.primed {
		s.primed = true
		return nil, nil
	}
	pids, e := pdhValues(s.pids)
	if e != nil {
		return nil, e
	}
	tids, e := pdhValues(s.tids)
	if e != nil {
		return nil, e
	}
	sw, e := pdhValues(s.switches)
	if e != nil {
		return nil, e
	}
	cp, e := pdhValues(s.cpu)
	if e != nil {
		return nil, e
	}
	out := []threadSample{}
	for name, pid := range pids {
		if pid > math.MaxUint32 {
			continue
		}
		p := selected[uint32(pid)]
		if p == nil || p.Done {
			continue
		}
		tid, ok := tids[name]
		if !ok || tid > math.MaxUint32 {
			continue
		}
		switches, ok := sw[name]
		if !ok {
			continue
		}
		cpu, ok := cp[name]
		if !ok {
			continue
		}
		out = append(out, threadSample{uint32(pid), uint32(tid), cpu, switches})
	}
	return out, nil
}
