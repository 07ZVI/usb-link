//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"runtime"
	"testing"
	"unsafe"
)

func TestWPDCallbackProjectsBothQueuesWithoutTDH(t *testing.T) {
	for _, id := range []uint16{2000, 2001} {
		provider := windows.GUID{Data1: 123}
		b := &localWPDTraceNative{critical: newWPDCriticalQueue(), summaryQueue: newWPDCriticalQueue(), stamp: func() int64 { return 77 }, allowed: func() bool { return true }}
		b.providers[1] = provider
		enumeration := privacyEnumeration(0)
		binary.LittleEndian.PutUint16(enumeration[8:], id)
		fixture := wpdMTPFixtures(t)[id]
		b.projections = wpdProjectionDefinitions("mtp", enumeration, func(d [16]byte) []byte {
			metadata := wpdMTPMetadata(id, fixture)
			copy(metadata[32:48], d[:])
			return metadata
		})
		if len(b.projections) != 1 {
			t.Fatal("fixture did not pass installed-template proof", id)
		}
		payload := wpdProjectionFixture(id)
		var pin runtime.Pinner
		pin.Pin(&payload[0])
		r := wpdEventRecord{Header: wpdEventHeader{Size: 112, Flags: 576, Provider: provider, Descriptor: wpdEventDescriptor{ID: id}, Timestamp: 134367552000000000, ThreadID: 42, ProcessID: 19}, BufferContext: 12, UserDataLength: uint16(len(payload))}
		(*wpdProjectionRecordView)(unsafe.Pointer(&r)).Data = &payload[0]
		b.record(&r)
		for i := range payload {
			payload[i] = 0xff
		}
		pin.Unpin()
		if b.data.DecodeCounts.Attempted != 0 || b.data.Decoded != 0 || b.data.Events != 1 {
			t.Fatal("callback advanced worker counters", b.data)
		}
		for _, q := range []*wpdCriticalQueue{b.critical, b.summaryQueue} {
			v, ok, _ := q.pop()
			if !ok {
				t.Fatal("projection missing", id)
			}
			assertWPDProjectionHasNoRaw(t, v)
			event, stage, code := decodeWPDCritical(&v)
			if stage != "decoded" || code != 0 || !event.OpcodeDecoded || event.CommandCode != 0x1002 || event.EventID != id || event.Provider != "mtp" || event.PID != 19 || event.MS != 77 || event.EventUTC != wpdEventSummary(r.Header, "mtp", 77).EventUTC || event.EventUTC == "" {
				t.Fatal("safe scalar projection changed", event, stage, code)
			}
			if itemShapeMismatch(v.recordShape(), 112, uint16(len(payload)), 576) || v.safeCorrelation().ThreadID != 42 || v.safeCorrelation().Attribution != "system_unattributed" {
				t.Fatal("safe context lost", v.recordShape(), v.safeCorrelation())
			}
			if id == 2001 && (!event.Response.CodeRead || event.Response.Code != 0x2001 || !event.Response.TransportRead || event.Response.TransportHR != 0x80004005) {
				t.Fatal("response scalar lost", event.Response)
			}
			if id == 2000 && event.Response != (wpdMTPResponse{}) {
				t.Fatal("command invented response", event.Response)
			}
			q.complete(true, false, false)
			if stats := q.snapshot(); stats.Decoded != 1 || stats.Failed != 0 || stats.Pending != 0 || stats.InFlight != 0 {
				t.Fatal(stats)
			}
		}
		runtime.KeepAlive(payload)
	}
}

func assertWPDProjectionHasNoRaw(t *testing.T, item wpdCriticalItem) {
	t.Helper()
	if !item.projected || item.payload != ([wpdCriticalPayloadLimit]byte{}) || item.header != ([wpdCriticalHeaderSize]byte{}) || item.length != 0 || item.bufferContext != 0 || item.provider != ([16]byte{}) || item.catalog != ([3][16]byte{}) {
		t.Fatal("projection retained raw record fields")
	}
}

func assertWPDCallbackRejection(t *testing.T, b *localWPDTraceNative, want string) {
	t.Helper()
	for _, q := range []*wpdCriticalQueue{b.critical, b.summaryQueue} {
		if stats := q.snapshot(); stats.Seen != 1 || stats.Enqueued != 1 || stats.Rejected != 0 || stats.Pending != 1 {
			t.Fatal("fixed rejection summary was not queued", stats)
		}
		item, ok, _ := q.pop()
		if !ok {
			t.Fatal("missing rejection summary")
		}
		assertWPDProjectionHasNoRaw(t, item)
		event, stage, native := decodeWPDCritical(&item)
		if stage != want || item.schema.Stage != want || native != 0 || event.OpcodeDecoded || event.CommandCode != 0 || event.Response != (wpdMTPResponse{}) {
			t.Fatal("wrong rejection gate", want, stage, event)
		}
		q.complete(false, false, false)
		if stats := q.snapshot(); stats.Failed != 1 || stats.Decoded != 0 || stats.InFlight != 0 || stats.Pending != 0 {
			t.Fatal("rejection was counted as successful decode", stats)
		}
	}
	if b.data.DecodeCounts.Attempted != 0 {
		t.Fatal("callback advanced worker counters")
	}
}

func TestWPDCallbackRejectsExtendedBeforeTouchingPayload(t *testing.T) {
	provider := windows.GUID{Data1: 123}
	b := &localWPDTraceNative{critical: newWPDCriticalQueue(), summaryQueue: newWPDCriticalQueue(), allowed: func() bool { return true }}
	b.providers[1] = provider
	// The invalid address must never be read. Only a fixed rejection summary is queued.
	r := wpdEventRecord{Header: wpdEventHeader{Size: 80, Provider: provider, Descriptor: wpdEventDescriptor{ID: 2001}}, ExtendedDataCount: 1, UserDataLength: 2, UserData: 1}
	b.record(&r)
	assertWPDCallbackRejection(t, b, "extended_data_unsupported")
}

func TestWPDCallbackRevocationRejectsBeforePayloadCopy(t *testing.T) {
	provider := windows.GUID{Data1: 123}
	b := &localWPDTraceNative{critical: newWPDCriticalQueue(), summaryQueue: newWPDCriticalQueue(), allowed: func() bool { return false }}
	b.providers[1] = provider
	r := wpdEventRecord{Header: wpdEventHeader{Size: 80, Provider: provider, Descriptor: wpdEventDescriptor{ID: 2000}}, UserDataLength: 2, UserData: 1}
	b.record(&r)
	if b.data.CaptureDenied != 1 || b.critical.snapshot().Seen != 0 || b.summaryQueue.snapshot().Seen != 0 || b.data.Events != 0 {
		t.Fatal("revoked callback entered capture")
	}
}

func TestWPDEventsLostSurvivesFinalCachedSample(t *testing.T) {
	b := &localWPDTraceNative{}
	if b.retainEventsLost(17) != 17 || b.retainEventsLost(0) != 17 || b.cachedSample().EventsLost != 17 {
		t.Fatal("observed ETW loss disappeared")
	}
	if b.retainEventsLost(23) != 23 || b.cachedSample().EventsLost != 23 {
		t.Fatal("later loss not retained")
	}
}

func itemShapeMismatch(s wpdRecordShape, size, payload, flags uint16) bool {
	return s.RecordBytes != size || s.HeaderBytes != 80 || s.UserDataBytes != payload || s.HeaderFlags != flags || s.ExtendedCount != 0
}
func TestWPDCallbackRejectsUndersizedRecordBeforeCopy(t *testing.T) {
	for _, size := range []uint16{0, 1, 79} {
		provider := windows.GUID{Data1: 123}
		b := &localWPDTraceNative{critical: newWPDCriticalQueue(), summaryQueue: newWPDCriticalQueue(), allowed: func() bool { return true }}
		b.providers[1] = provider
		r := wpdEventRecord{Header: wpdEventHeader{Size: size, Provider: provider, Descriptor: wpdEventDescriptor{ID: 2000}}, UserDataLength: 2, UserData: 1}
		b.record(&r)
		assertWPDCallbackRejection(t, b, "header_size_invalid")
	}
}
