//go:build windows && amd64

package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"unicode/utf16"
	"unsafe"
)

func batchedProcessList() (map[uint32]processEntry, error) {
	var layout windows.SYSTEM_PROCESS_INFORMATION
	if unsafe.Sizeof(layout) != 256 || unsafe.Offsetof(layout.ImageName) != 56 || unsafe.Offsetof(layout.UniqueProcessID) != 80 || unsafe.Offsetof(layout.InheritedFromUniqueProcessID) != 88 {
		return nil, fmt.Errorf("system process layout mismatch")
	}
	size := uint32(1 << 20)
	for attempts := 0; attempts < 4; attempts++ {
		b := make([]byte, size)
		var used uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(&b[0]), size, &used)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH {
			if used > 16<<20 || size >= 16<<20 {
				return nil, fmt.Errorf("system process snapshot too large")
			}
			size = max(size*2, used)
			if size > 16<<20 {
				size = 16 << 20
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if used < 256 || used > size {
			return nil, fmt.Errorf("system process result bounds")
		}
		rows, err := decodeProcessSnapshot(b[:used], uint64(uintptr(unsafe.Pointer(&b[0]))))
		runtime.KeepAlive(b)
		if err != nil {
			return nil, err
		}
		out := make(map[uint32]processEntry, len(rows))
		for _, row := range rows {
			entry := processEntry{PID: row.pid, Parent: row.parent, Threads: row.threads}
			copy(entry.Name[:], utf16.Encode([]rune(row.name)))
			out[row.pid] = entry
		}
		return out, nil
	}
	return nil, fmt.Errorf("system process snapshot did not stabilize")
}
