package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"
)

type snapshotEntry struct {
	pid, parent, threads uint32
	name                 string
}

// Decode the amd64 SYSTEM_PROCESS_INFORMATION layout with offsets verified
// against x/sys/windows by the Windows caller. Never follow unchecked pointers.
func decodeProcessSnapshot(b []byte, base uint64) ([]snapshotEntry, error) {
	var out []snapshotEntry
	seen := map[uint32]bool{}
	for off := 0; ; {
		if off > len(b) || len(b)-off < 256 {
			return nil, fmt.Errorf("process header bounds")
		}
		r := b[off:]
		next := uint64(binary.LittleEndian.Uint32(r))
		pid, parent := binary.LittleEndian.Uint64(r[80:]), binary.LittleEndian.Uint64(r[88:])
		if pid > math.MaxUint32 || parent > math.MaxUint32 || seen[uint32(pid)] {
			return nil, fmt.Errorf("process identity bounds")
		}
		seen[uint32(pid)] = true
		n := uint64(binary.LittleEndian.Uint16(r[56:]))
		maximum := uint64(binary.LittleEndian.Uint16(r[58:]))
		ptr := binary.LittleEndian.Uint64(r[64:])
		if n%2 != 0 || n > maximum || n > 518 {
			return nil, fmt.Errorf("process name length bounds")
		}
		var name string
		if n > 0 {
			if ptr < base || ptr-base > uint64(len(b)) || n > uint64(len(b))-(ptr-base) {
				return nil, fmt.Errorf("process name pointer bounds")
			}
			p := int(ptr - base)
			units := make([]uint16, n/2)
			for i := range units {
				units[i] = binary.LittleEndian.Uint16(b[p+i*2:])
			}
			name = string(utf16.Decode(units))
		}
		out = append(out, snapshotEntry{uint32(pid), uint32(parent), binary.LittleEndian.Uint32(r[4:]), name})
		if next == 0 {
			return out, nil
		}
		if next < 256 || next%8 != 0 || next > uint64(len(b)-off) {
			return nil, fmt.Errorf("process next bounds")
		}
		off += int(next)
	}
}
