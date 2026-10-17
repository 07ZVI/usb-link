package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUSBTraceSessionMetadataIsNotAUSBRejection(t *testing.T) {
	s := newUSBTraceStatus()
	// A trace header can exceed the USB scalar bound. Its data must be ignored.
	h := usbTraceCallbackHeader{Size: 80, ID: 0, Opcode: 0, DataLength: 4096, ExtendedCount: 1}
	for i := 0; i < 6; i++ {
		if s.admitHeader("session_metadata", h) {
			t.Fatal("session body was admitted")
		}
	}
	if s.CallbacksReceived != 6 || s.SessionMetadata != 6 || s.SessionHeaders != 6 || s.Received != 0 || s.SchemaRejected != 0 || s.RejectedHeaderCount != 0 || s.Coverage != "not_covered" {
		t.Fatal("session metadata misreported as lost USB evidence", s)
	}
	// ID zero from a known USB provider is still a provider event.
	if !s.admitHeader("USBHUB3", usbTraceCallbackHeader{Size: 80, ID: 0}) || s.Received != 1 || s.SessionMetadata != 6 {
		t.Fatal("ID zero alone was classified as metadata")
	}
}

func TestUSBTraceHeaderAccountingSeparatesSourcesAndBadShapes(t *testing.T) {
	s := newUSBTraceStatus()
	if s.admitHeader("other_provider", usbTraceCallbackHeader{Size: 80, ID: 0, DataLength: 65535}) {
		t.Fatal("foreign body admitted")
	}
	if s.admitHeader("USBHUB3", usbTraceCallbackHeader{Size: 79}) {
		t.Fatal("short header admitted")
	}
	for _, h := range []usbTraceCallbackHeader{{Size: 80, Flags: 4}, {Size: 80, ExtendedCount: 1}, {Size: 80, DataLength: 33, HasData: true}, {Size: 80, DataLength: 1}} {
		if s.admitHeader("UCX", h) {
			t.Fatal("bad provider shape admitted", h)
		}
	}
	if s.CallbacksReceived != s.SessionMetadata+s.UnknownProvider+s.HeaderRejected+s.Received || s.Received != 4 || s.ShapeRejected != 4 || s.SchemaRejected != 4 || s.UnknownProvider != 1 || s.HeaderRejected != 1 {
		t.Fatal("callback source counts do not reconcile", s)
	}
}

func TestUSBTraceRejectionSignaturesAreBoundedAndContainNoArbitraryText(t *testing.T) {
	s := newUSBTraceStatus()
	for i := 0; i < 12; i++ {
		h := usbTraceCallbackHeader{Size: 80, ID: uint16(i), Version: 1, Opcode: 3}
		s.rejectHeader("PRIVATE_DEVICE_PATH", "PRIVATE_BODY", h)
	}
	if s.RejectedHeaderCount != 8 || s.RejectedHeaderOmitted != 4 {
		t.Fatal("signature bound not reported", s)
	}
	s.rejectHeader("other_provider", "unknown_rejection", usbTraceCallbackHeader{Size: 80, ID: 0, Version: 1, Opcode: 3})
	if s.RejectedHeaders[0].Count != 2 || s.RejectedHeaderOmitted != 4 {
		t.Fatal("duplicate signature did not aggregate")
	}
	b, err := json.Marshal(s)
	if err != nil || strings.Contains(string(b), "PRIVATE") {
		t.Fatal("arbitrary rejected text was retained", err)
	}
	copy := s
	copy.RejectedHeaders[0].Count = 999
	if s.RejectedHeaders[0].Count == 999 {
		t.Fatal("snapshot aliases rejection history")
	}
}
