//go:build usblink_local_remote

package ipadncm

import "encoding/binary"

// Only this installed, fully reviewed layout can be projected in callback memory.
// The event-ID filter cannot exclude versions, so every installed version must match.
type wpdProjectionDefinition struct{ Descriptor [16]byte }

func wpdProjectionDefinitions(provider string, enumeration []byte, metadata func([16]byte) []byte) []wpdProjectionDefinition {
	if provider != "mtp" || len(enumeration) < 8 || len(enumeration) > 65536 {
		return nil
	}
	n := binary.LittleEndian.Uint32(enumeration)
	if n > 4095 || uint64(n)*16+8 != uint64(len(enumeration)) {
		return nil
	}
	var result []wpdProjectionDefinition
	for _, id := range []uint16{2000, 2001} {
		var candidates []wpdProjectionDefinition
		seen := map[[16]byte]bool{}
		bad := false
		for i := uint32(0); i < n; i++ {
			var d [16]byte
			copy(d[:], enumeration[8+i*16:8+(i+1)*16])
			if binary.LittleEndian.Uint16(d[:]) != id {
				continue
			}
			b := metadata(d)
			if seen[d] || len(b) < 112 || string(b[32:48]) != string(d[:]) || len(wpdExactMTPCommandField(provider, id, d[2], b)) != 1 {
				bad = true
				continue
			}
			seen[d] = true
			// Maps/custom structures have not been reviewed, even if six columns match.
			_, count := wpdMTPCommandDefinition(id)
			for p := 0; p < int(count); p++ {
				if binary.LittleEndian.Uint32(b[112+p*24+12:]) != 0 {
					bad = true
				}
			}
			candidates = append(candidates, wpdProjectionDefinition{d})
		}
		if !bad {
			result = append(result, candidates...)
		}
	}
	return result
}

// read returns one fixed-width integer from borrowed callback memory. Array and
// binary contents are never read, copied, or retained; only their lengths skip them.
func wpdProjectMTP(id uint16, length uint16, read func(int, int) uint64) (uint16, wpdMTPResponse, string) {
	var response wpdMTPResponse
	if id != 2000 && id != 2001 {
		return 0, response, "event_not_selected"
	}
	end := uint64(length)
	if end < 14 || end > wpdCriticalPayloadLimit {
		return 0, response, "payload_size_invalid"
	}
	command := uint16(read(8, 2))
	pos := uint64(14) + read(10, 4)*4
	if pos > end {
		return 0, response, "payload_layout_invalid"
	}
	if id == 2000 {
		if pos != end {
			return 0, response, "payload_layout_invalid"
		}
		return command, response, "decoded"
	}
	if end-pos < 10 {
		return 0, response, "payload_layout_invalid"
	}
	hr := uint32(read(int(pos), 4))
	code := uint16(read(int(pos)+4, 2))
	pos += 10 + read(int(pos)+6, 4)*4
	if pos > end || end-pos < 4 {
		return 0, response, "payload_layout_invalid"
	}
	body := read(int(pos), 4)
	pos += 4
	if body != end-pos {
		return 0, response, "payload_layout_invalid"
	}
	response.CodeRead = true
	response.Code = code
	response.TransportRead = true
	response.TransportHR = hr
	return command, response, "decoded"
}
