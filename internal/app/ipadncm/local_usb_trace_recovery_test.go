package ipadncm

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func usbTraceOwnershipFixture() ([]byte, usbTraceQueryEvidence, string) {
	raw := make([]byte, 512)
	name := "USBLink-USBMetadata-0123456789abcdef0123456789abcdef"
	for i, r := range utf16.Encode([]rune(name)) {
		binary.LittleEndian.PutUint16(raw[120+2*i:], r)
	}
	return raw, usbTraceQueryEvidence{GUIDMatches: true, Mode: 0x100, NameOffset: 120, FileOffset: 256, BufferBytes: 512}, name
}

func TestUSBTraceQueryEmptyFileOutputIsNotFileLogging(t *testing.T) {
	raw, q, name := usbTraceOwnershipFixture()
	for _, offset := range []uint32{0, 256, 510} {
		q.FileOffset = offset
		got := usbTraceCompareQuery(raw, q, name)
		if got.Mismatch != 0 || !got.FileValid || !got.FileEmpty || !got.NameMatches {
			t.Fatalf("empty output offset %d: %+v", offset, got)
		}
	}
}

func TestUSBTraceQueryOwnershipStillRejectsEveryForeignProperty(t *testing.T) {
	raw, base, name := usbTraceOwnershipFixture()
	for _, tc := range []struct {
		change func(*usbTraceQueryEvidence)
		want   uint32
	}{
		{func(q *usbTraceQueryEvidence) { q.GUIDMatches = false }, 1},
		{func(q *usbTraceQueryEvidence) { q.NameOffset = 256 }, 2},
		{func(q *usbTraceQueryEvidence) { q.Mode = 0x101 }, 4},
		{func(q *usbTraceQueryEvidence) { q.Mode = 0 }, 4},
		{func(q *usbTraceQueryEvidence) { q.MaxFile = 8 }, 8},
		{func(q *usbTraceQueryEvidence) { q.FileOffset = 511 }, 16},
		{func(q *usbTraceQueryEvidence) { q.FileOffset = 512 }, 16},
		{func(q *usbTraceQueryEvidence) { q.FileOffset = 118 }, 16},
		{func(q *usbTraceQueryEvidence) { q.BufferBytes = 119 }, 32},
		{func(q *usbTraceQueryEvidence) { q.BufferBytes = 513 }, 32},
	} {
		q := base
		tc.change(&q)
		got := usbTraceCompareQuery(raw, q, name)
		if got.Mismatch&tc.want == 0 {
			t.Fatalf("lost mismatch %d: %+v", tc.want, got)
		}
	}
	copyRaw := append([]byte(nil), raw...)
	copyRaw[256] = 'C'
	copyRaw[258] = ':'
	got := usbTraceCompareQuery(copyRaw, base, name)
	if got.Mismatch&16 == 0 || got.FileEmpty {
		t.Fatal("file path allowed")
	}
	serialized, _ := json.Marshal(got)
	if strings.Contains(string(serialized), name) || strings.Contains(string(serialized), "C:") {
		t.Fatal("identity escaped diagnostics")
	}
	for i := 256; i < len(copyRaw); i += 2 {
		copyRaw[i] = 65
	}
	if got := usbTraceCompareQuery(copyRaw, base, name); got.Mismatch&16 == 0 || got.FileValid {
		t.Fatal("unterminated file allowed")
	}
}

func TestUSBTraceQueryFailureSurvivesSuccessfulCleanupQuery(t *testing.T) {
	usbTraceResetQueries()
	defer usbTraceResetQueries()
	bad := usbTraceQueryEvidence{Observed: true, Mode: 0x101, Mismatch: 4}
	usbTraceRecordQuery(bad)
	usbTraceRecordQuery(usbTraceQueryEvidence{Observed: true, NativeCode: 4201})
	last, first := usbTraceQuerySnapshot()
	if last.NativeCode != 4201 || first != bad {
		t.Fatal("failure overwritten")
	}
	first.Mode = 0
	_, copy := usbTraceQuerySnapshot()
	if copy.Mode != 0x101 {
		t.Fatal("snapshot alias")
	}
}

func TestUSBTraceSecondStopCannotClearFailedRecovery(t *testing.T) {
	var r usbTraceStopResult
	failure := errors.New("USB_TRACE_SESSION_NOT_OWNED")
	r.finish(failure)
	r.finish(nil)
	if !r.done || r.err != failure {
		t.Fatal("second cleanup cleared recovery failure")
	}
	var success usbTraceStopResult
	success.finish(nil)
	success.finish(failure)
	if !success.done || success.err != nil {
		t.Fatal("completed stop changed retrospectively")
	}
}

func TestUSBTraceDocumentedHybridPolicyOnly(t *testing.T) {
	raw, q, name := usbTraceOwnershipFixture()
	for _, mode := range []uint32{0x100, 0x00400100, 0x00800100} {
		q.Mode = mode
		if got := usbTraceCompareQuery(raw, q, name); got.Mismatch != 0 {
			t.Fatalf("known lifecycle policy %x rejected: %+v", mode, got)
		}
		foreign := q
		foreign.GUIDMatches = false
		if got := usbTraceCompareQuery(raw, foreign, name); got.Mismatch&1 == 0 {
			t.Fatal("hybrid flag bypassed GUID")
		}
		if got := usbTraceCompareQuery(raw, q, "foreign-session"); got.Mismatch&2 == 0 {
			t.Fatal("hybrid flag bypassed name")
		}
	}
	for _, mode := range []uint32{0, 0x00400000, 0x00800000, 0x00c00100, 0x00800101, 0x00400102, 0x10000100, 0x08000100, 0x02000100, 0x80000100, 0xffffffff} {
		q.Mode = mode
		if got := usbTraceCompareQuery(raw, q, name); got.Mismatch&4 == 0 {
			t.Fatalf("unowned mode %x admitted", mode)
		}
	}
	for _, mode := range []uint32{0x00400100, 0x00800100} {
		q.Mode = mode
		q.MaxFile = 8
		if got := usbTraceCompareQuery(raw, q, name); got.Mismatch&8 == 0 {
			t.Fatal("hybrid flag bypassed maxfile")
		}
		q.MaxFile = 0
		raw[256] = 'X'
		if got := usbTraceCompareQuery(raw, q, name); got.Mismatch&16 == 0 {
			t.Fatal("hybrid flag bypassed filename")
		}
		raw[256] = 0
	}
}
