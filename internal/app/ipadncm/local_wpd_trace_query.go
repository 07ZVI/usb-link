package ipadncm

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Mismatch bits: 1 GUID, 2 name encoding/range, 4 name identity,
// 8 file encoding/range, 16 mode/size/file identity. No names or paths escape.
type wpdSessionQueryEvidence struct {
	Schema     int    `json:"schema"`
	Mode       uint32 `json:"mode"`
	MaxFileMiB uint32 `json:"max_file_mib"`
	NameOffset uint32 `json:"name_offset"`
	FileOffset uint32 `json:"file_offset"`
	BufferSize uint32 `json:"buffer_bytes"`
	Mismatch   uint32 `json:"mismatch_bits"`
}

func wpdCheckSessionQuery(j localWPDTraceJournal, expectedPath string, raw []byte, guidMatch bool, mode, maxFile, nameOffset, fileOffset uint32) wpdSessionQueryEvidence {
	d := wpdSessionQueryEvidence{Schema: j.Schema, Mode: mode, MaxFileMiB: maxFile, NameOffset: nameOffset, FileOffset: fileOffset, BufferSize: uint32(len(raw))}
	if !guidMatch {
		d.Mismatch |= 1
	}
	name, nameOK := wpdQueryString(raw, nameOffset)
	if !nameOK {
		d.Mismatch |= 2
	} else if name != j.Session {
		d.Mismatch |= 4
	}
	file, fileOK := "", true
	if fileOffset != 0 {
		file, fileOK = wpdQueryString(raw, fileOffset)
	}
	if !fileOK {
		d.Mismatch |= 8
	}
	if !j.valid() || !wpdSessionModeOwned(j, mode, maxFile, strings.ToLower(file), strings.ToLower(expectedPath)) {
		d.Mismatch |= 16
	}
	return d
}

// Unlike the display-only UTF16 helper, an invalid output must not turn into
// an apparently empty filename. Only strings outside the native header qualify.
func wpdQueryString(raw []byte, offset uint32) (string, bool) {
	if offset < 120 || offset%2 != 0 || uint64(offset)+2 > uint64(len(raw)) {
		return "", false
	}
	u := make([]uint16, 0, 128)
	for i := int(offset); i+1 < len(raw) && len(u) <= 1023; i += 2 {
		v := binary.LittleEndian.Uint16(raw[i:])
		if v == 0 {
			for n := 0; n < len(u); n++ {
				if u[n] >= 0xd800 && u[n] <= 0xdbff {
					if n+1 >= len(u) || u[n+1] < 0xdc00 || u[n+1] > 0xdfff {
						return "", false
					}
					n++
				} else if u[n] >= 0xdc00 && u[n] <= 0xdfff {
					return "", false
				}
			}
			return string(utf16.Decode(u)), true
		}
		u = append(u, v)
	}
	return "", false
}
