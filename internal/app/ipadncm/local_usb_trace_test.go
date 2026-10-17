package ipadncm

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func usbTraceFixture(name string, in uint16) ([]byte, [16]byte, [16]byte) {
	d := [16]byte{7, 0, 1}
	g := [16]byte{1, 2, 3}
	b := make([]byte, 136)
	copy(b, g[:])
	copy(b[32:], d[:])
	binary.LittleEndian.PutUint32(b[100:], 1)
	binary.LittleEndian.PutUint32(b[104:], 1)
	p := b[112:]
	binary.LittleEndian.PutUint32(p[4:], 136)
	binary.LittleEndian.PutUint16(p[8:], in)
	binary.LittleEndian.PutUint16(p[16:], 1)
	for _, v := range utf16.Encode([]rune(name + "\x00")) {
		b = append(b, byte(v), byte(v>>8))
	}
	return b, d, g
}
func TestUSBTraceWholeTemplateSafety(t *testing.T) {
	for _, name := range []string{"PortNumber", "EndpointAddress", "Status"} {
		b, d, g := usbTraceFixture(name, 8)
		s, e := usbTraceSafeSchema(b, d, g)
		if e != "" || s.Bytes != 4 {
			t.Fatalf("safe %s: %s", name, e)
		}
	}
	for _, name := range []string{"Payload", "SerialNumber", "DeviceHandle", "Hub", "IRP", "HostID", "Data", "Unknown"} {
		b, d, g := usbTraceFixture(name, 8)
		if _, e := usbTraceSafeSchema(b, d, g); e == "" {
			t.Fatalf("accepted %s", name)
		}
	}
	for _, in := range []uint16{1, 2, 9, 10, 11, 14, 15, 16, 21, 300} {
		b, d, g := usbTraceFixture("Status", in)
		if _, e := usbTraceSafeSchema(b, d, g); e == "" {
			t.Fatalf("accepted type %d", in)
		}
	}
	for _, mutate := range []func([]byte){func(b []byte) { b[112] = 1 }, func(b []byte) { b[112] = 0x20 }, func(b []byte) { b[128] = 2 }, func(b []byte) { b[124] = 1 }, func(b []byte) { b[122] = 1 }, func(b []byte) { b[48] = 1 }, func(b []byte) { b[104] = 0 }, func(b []byte) { b[0] = 8 }, func(b []byte) { b[32] = 8 }} {
		b, d, g := usbTraceFixture("Status", 8)
		mutate(b)
		if _, e := usbTraceSafeSchema(b, d, g); e == "" {
			t.Fatal("accepted changed template")
		}
	}
}
func TestUSBTraceAnyUnsafeVersionRejectsID(t *testing.T) {
	b, d, g := usbTraceFixture("Status", 8)
	s, e := usbTraceSafeSchema(b, d, g)
	if e != "" {
		t.Fatal(e)
	}
	other := s
	other.Descriptor[2] = 2
	ids, safe := usbTraceSafeIDs([]usbTraceSchema{s, other}, map[uint16]bool{7: true})
	if len(ids) != 0 || len(safe) != 0 {
		t.Fatal("unsafe version admitted")
	}
	ids, safe = usbTraceSafeIDs([]usbTraceSchema{s, other}, nil)
	if len(ids) != 1 || len(safe) != 2 {
		t.Fatal("valid versions lost")
	}
}
func TestUSBTraceExactPayloadAndValueCopy(t *testing.T) {
	b, d, g := usbTraceFixture("Status", 8)
	s, _ := usbTraceSafeSchema(b, d, g)
	raw := []byte{9, 0, 0, 0}
	e, ok := usbTraceDecode(s, raw)
	raw[0] = 42
	if !ok || e.Values[0].Value != 9 || e.TargetScope != "unknown" {
		t.Fatal(e)
	}
	for _, p := range [][]byte{nil, {1, 2, 3}, {1, 2, 3, 4, 5}} {
		if _, ok := usbTraceDecode(s, p); ok {
			t.Fatal("length accepted")
		}
	}
	s.Fields[0].InType = 13
	if _, ok := usbTraceDecode(s, []byte{2, 0, 0, 0}); ok {
		t.Fatal("invalid bool")
	}
}
func TestUSBTraceSnapshotBudget(t *testing.T) {
	s := newUSBTraceStatus()
	s.Error = "USB_TRACE_SESSION_NOT_OWNED"
	s.RecentCount = 4
	for i := range s.Recent {
		s.Recent[i] = usbTraceEvent{Provider: "USBHUB3", TargetScope: "unknown", Count: 8, ReceivedUTC: "2026-10-17T23:59:59.123456789Z"}
		for j := range s.Recent[i].Values {
			s.Recent[i].Values[j] = usbTraceValue{"ConfigurationValue", ^uint32(0)}
		}
	}
	copy := s
	copy.Recent[0].Values[0].Value = 1
	if s.Recent[0].Values[0].Value == 1 {
		t.Fatal("snapshot alias")
	}
	b, e := json.Marshal(map[string]any{"local_usb_trace": s})
	if e != nil || len(b) > 8192 {
		t.Fatalf("budget %d %v", len(b), e)
	}
	if strings.Contains(string(b), "payload") {
		t.Fatal("payload field")
	}
}

func TestUSBTraceIDLimitIsExplicit(t *testing.T) {
	var schemas []usbTraceSchema
	for i := 0; i < 70; i++ {
		v := usbTraceSchema{}
		binary.LittleEndian.PutUint16(v.Descriptor[:], uint16(i))
		schemas = append(schemas, v)
	}
	ids, safe := usbTraceSafeIDs(schemas, nil)
	if len(ids) != 64 || len(safe) != 64 || usbTraceOmittedIDs(schemas, nil, len(ids)) != 6 {
		t.Fatal("limit not accounted")
	}
}
func TestUSBTraceIncompleteTemplateNeverAdmitted(t *testing.T) {
	b, d, g := usbTraceFixture("PortNumber", 8)
	for _, cut := range []int{0, 111, 112, 135, len(b) - 1, len(b) - 2} {
		if _, reason := usbTraceSafeSchema(b[:cut], d, g); reason == "" {
			t.Fatalf("cut %d admitted", cut)
		}
	}
	binary.LittleEndian.PutUint32(b[100:], 2)
	if _, reason := usbTraceSafeSchema(b, d, g); reason == "" {
		t.Fatal("hidden second property admitted")
	}
}
func TestUSBTraceSourceTimeDoesNotUseWorkerTime(t *testing.T) {
	if usbTraceEventUTC(0) != "" || usbTraceEventUTC(-1) != "" {
		t.Fatal("unknown timestamp fabricated")
	}
	if got := usbTraceEventUTC(116444736000000000); got != "1970-01-01T00:00:00Z" {
		t.Fatal(got)
	}
}
func TestUSBTraceInvalidScalarLayoutCannotReadBeyondPayload(t *testing.T) {
	s := usbTraceSchema{Count: 1, Bytes: 1}
	s.Fields[0] = wpdManifestField{Name: "Status", InType: 8}
	if _, ok := usbTraceDecode(s, []byte{1}); ok {
		t.Fatal("width mismatch")
	}
	s.Count = 9
	if _, ok := usbTraceDecode(s, []byte{1}); ok {
		t.Fatal("field overflow")
	}
}

func TestUSBTraceConsumerExitCannotBeReactivated(t *testing.T) {
	if !usbTraceCanAdmit(true, true, false, false) {
		t.Fatal("live consumer rejected")
	}
	for _, v := range [][4]bool{{true, true, true, false}, {false, true, false, false}, {true, false, false, false}, {true, true, false, true}, {true, true, true, true}} {
		if usbTraceCanAdmit(v[0], v[1], v[2], v[3]) {
			t.Fatalf("unsafe activation %v", v)
		}
	}
}

func TestUSBTraceCanonicalScalarOutput(t *testing.T) {
	for _, pair := range [][2]uint16{{4, 4}, {6, 6}, {8, 8}, {13, 13}, {20, 18}} {
		b, d, g := usbTraceFixture("Status", pair[0])
		binary.LittleEndian.PutUint16(b[122:], pair[1])
		binary.LittleEndian.PutUint16(b[130:], uint16(usbTraceScalarSize(pair[0])))
		if _, reason := usbTraceSafeSchema(b, d, g); reason != "" {
			t.Fatalf("canonical %v: %s", pair, reason)
		}
		for _, bad := range []uint16{1, 2, 14, 15, 19, 20, 21, 22, 23, 24, 28, 32, 300} {
			binary.LittleEndian.PutUint16(b[122:], bad)
			if _, reason := usbTraceSafeSchema(b, d, g); reason == "" {
				t.Fatalf("unsafe out %d for %d", bad, pair[0])
			}
		}
	}
}

func TestUSBTraceNeverUsesAllKeywordsMask(t *testing.T) {
	if !usbTraceKeywordMaskSafe(1, 6) {
		t.Fatal("safe keyword rejected")
	}
	for _, v := range [][2]uint64{{0, 6}, {7, 6}, {1, 0}, {^uint64(0), 6}} {
		if usbTraceKeywordMaskSafe(v[0], v[1]) {
			t.Fatal("unproven keyword mask admitted")
		}
	}
}

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
