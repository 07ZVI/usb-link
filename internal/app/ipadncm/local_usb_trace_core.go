package ipadncm

import (
	"encoding/binary"
	"unicode/utf16"
)

// Query evidence contains only comparisons and native scalar properties.
// Neither arbitrary native strings nor the protected session identity escape.
type usbTraceQueryEvidence struct {
	Observed    bool   `json:"observed"`
	NativeCode  uint32 `json:"native_code"`
	GUIDMatches bool   `json:"guid_matches"`
	NameMatches bool   `json:"name_matches"`
	NameValid   bool   `json:"name_valid"`
	FileValid   bool   `json:"file_valid"`
	FileEmpty   bool   `json:"file_empty"`
	Mode        uint32 `json:"mode"`
	MaxFile     uint32 `json:"max_file"`
	NameOffset  uint32 `json:"name_offset"`
	FileOffset  uint32 `json:"file_offset"`
	BufferBytes uint32 `json:"buffer_bytes"`
	Mismatch    uint32 `json:"mismatch"`
}

func usbTraceCompareQuery(raw []byte, q usbTraceQueryEvidence, expectedName string) usbTraceQueryEvidence {
	q.Observed = true
	if q.BufferBytes < 120 || uint64(q.BufferBytes) > uint64(len(raw)) {
		q.Mismatch |= 32
		return q
	}
	raw = raw[:q.BufferBytes]
	name, valid := usbTraceQueryText(raw, q.NameOffset)
	q.NameValid = valid
	q.NameMatches = valid && name == expectedName
	q.FileEmpty = q.FileOffset == 0
	q.FileValid = q.FileEmpty
	if q.FileOffset != 0 {
		file, valid := usbTraceQueryText(raw, q.FileOffset)
		q.FileValid = valid
		q.FileEmpty = valid && file == ""
	}
	if !q.GUIDMatches {
		q.Mismatch |= 1
	}
	if !q.NameMatches {
		q.Mismatch |= 2
	}
	if !usbTraceSessionModeOwned(q.Mode) {
		q.Mismatch |= 4
	}
	if q.MaxFile != 0 {
		q.Mismatch |= 8
	}
	if !q.FileValid || !q.FileEmpty {
		q.Mismatch |= 16
	}
	return q
}

const usbTraceRealtimeMode uint32 = 0x00000100

const usbTraceStopOnHybridShutdown uint32 = 0x00400000

func usbTraceQueryText(raw []byte, offset uint32) (string, bool) {
	if offset < 120 || offset%2 != 0 || uint64(offset)+2 > uint64(len(raw)) {
		return "", false
	}
	var value []uint16
	for i := int(offset); i+1 < len(raw) && len(value) < 1024; i += 2 {
		v := binary.LittleEndian.Uint16(raw[i:])
		if v == 0 {
			return string(utf16.Decode(value)), true
		}
		value = append(value, v)
	}
	return "", false
}

// Windows may add exactly one documented hybrid-shutdown policy when an
// older receipt's session was created without an explicit policy.
func usbTraceSessionModeOwned(mode uint32) bool {
	switch mode {
	case usbTraceRealtimeMode, usbTraceRealtimeMode | usbTraceStopOnHybridShutdown, usbTraceRealtimeMode | usbTracePersistOnHybridShutdown:
		return true
	default:
		return false
	}
}

const usbTracePersistOnHybridShutdown uint32 = 0x00800000
