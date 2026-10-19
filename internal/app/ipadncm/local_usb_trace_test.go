//go:build usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"encoding/json"
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
