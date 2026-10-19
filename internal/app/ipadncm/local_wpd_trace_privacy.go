//go:build usblink_local_remote

package ipadncm

import "encoding/binary"

// Event-ID filters do not filter versions. Every installed definition for an
// admitted ID must be safe before the provider can write to this session.
func wpdSafeEventIDs(provider string, enumeration []byte, metadata func([16]byte) []byte) []uint16 {
	if len(enumeration) < 8 || len(enumeration) > 65536 {
		return nil
	}
	n := binary.LittleEndian.Uint32(enumeration)
	if n > 4095 || uint64(n)*16+8 != uint64(len(enumeration)) {
		return nil
	}
	var out []uint16
	for _, target := range wpdManifestTargets {
		if [3]string{"api", "mtp", "usb"}[target.Provider] != provider {
			continue
		}
		found, safe := false, true
		seen := map[[16]byte]bool{}
		for i := uint32(0); i < n; i++ {
			var d [16]byte
			copy(d[:], enumeration[8+i*16:8+(i+1)*16])
			if binary.LittleEndian.Uint16(d[:]) != target.ID {
				continue
			}
			if seen[d] {
				safe = false
				break
			}
			seen[d] = true
			found = true
			b := metadata(d)
			if len(b) < 112 || string(b[32:48]) != string(d[:]) || !wpdWholeEventSafe(b) {
				safe = false
				break
			}
		}
		if found && safe {
			out = append(out, target.ID)
		}
	}
	return out
}

// This whitelist describes the entire event, not fields selected after ETW has
// already captured it. Arrays, strings, binary data and unknown scalar semantics
// are rejected even when a familiar opcode field is present.
func wpdWholeEventSafe(metadata []byte) bool {
	f, n, top, stage := wpdManifestDefinition(metadata)
	if stage != "complete" || n == 0 || n != top {
		return false
	}
	for i, p := range f[:n] {
		// Map/custom metadata is outside the reviewed scalar definition.
		if binary.LittleEndian.Uint32(metadata[112+i*24+12:]) != 0 {
			return false
		}
		if p.Flags != 0 || p.Count != 1 {
			return false
		}
		var size uint16
		switch p.Name {
		case "MTP_Opcode", "MTP_Response_Code", "MTP_Event_Code":
			size = 2
		case "MTP_Response_Retrieval_HR_From_Transport", "MTP_Event_Retrieval_HR_From_Transport":
			size = 4
		default:
			return false
		}
		in := uint16(6)
		if size == 4 {
			in = 8
		}
		if p.InType != in || p.OutType != in || p.Length != size {
			return false
		}
	}
	return true
}

// EVENT_FILTER_EVENT_ID: BOOLEAN, reserved byte, USHORT count, USHORT IDs.
func wpdEventIDFilter(ids []uint16) []byte {
	if len(ids) == 0 || len(ids) > 64 {
		return nil
	}
	b := make([]byte, 4+len(ids)*2)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:], uint16(len(ids)))
	seen := map[uint16]bool{}
	for i, id := range ids {
		if id == 0 || seen[id] {
			return nil
		}
		seen[id] = true
		binary.LittleEndian.PutUint16(b[4+i*2:], id)
	}
	return b
}
