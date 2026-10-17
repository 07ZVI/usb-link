//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"runtime"
	"testing"
	"unsafe"
)

func TestWPDNativeProjectionQueuesNoPayload(t *testing.T) {
	data := wpdProjectionFixture(2001)
	provider := windows.GUID{Data1: 1}
	record := wpdEventRecord{Header: wpdEventHeader{Size: 80, Provider: provider}}
	record.Header.Descriptor.ID = 2001
	record.UserDataLength = uint16(len(data))
	(*wpdProjectionRecordView)(unsafe.Pointer(&record)).Data = &data[0]
	var pin runtime.Pinner
	pin.Pin(&data[0])
	defer pin.Unpin()
	var descriptor [16]byte
	copy(descriptor[:], unsafe.Slice((*byte)(unsafe.Pointer(&record.Header.Descriptor)), 16))
	b := &localWPDTraceNative{projections: []wpdProjectionDefinition{{Descriptor: descriptor}}, critical: newWPDCriticalQueue(), summaryQueue: newWPDCriticalQueue()}
	item := b.projectRecord(&record, provider, 100, 2)
	if !item.event.OpcodeDecoded || item.event.Response.Code != 0x2001 || item.stage != "decoded" {
		t.Fatal(item.event, item.stage)
	}
	b.captureCriticalProjection(&record, item)
	b.captureSummaryProjection(&record, item)
	for _, q := range []*wpdCriticalQueue{b.critical, b.summaryQueue} {
		v, ok, _ := q.pop()
		if !ok || v.payload != ([4096]byte{}) || v.header != ([80]byte{}) {
			t.Fatal("private payload in queue")
		}
		event, stage, _ := decodeWPDCritical(&v)
		if stage != "decoded" || event.CommandCode != 0x1002 {
			t.Fatal(event, stage)
		}
	}
	// Same ID with changed descriptor must not touch even an invalid data pointer.
	record.Header.Descriptor.Version = 1
	record.UserData = 1
	if got := b.projectRecord(&record, provider, 0, 0); got.event.OpcodeDecoded || got.stage != "version_not_selected" {
		t.Fatal(got.stage)
	}
	record.Header.Descriptor.Version = 0
	record.Header.Descriptor.Task = 1
	if got := b.projectRecord(&record, provider, 0, 0); got.event.OpcodeDecoded || got.stage != "strict_manifest_template_mismatch" {
		t.Fatal(got.stage)
	}
	runtime.KeepAlive(data)
}
func TestWPDNativeProjectionRevokedCallbackNeverReads(t *testing.T) {
	b := &localWPDTraceNative{allowed: func() bool { return false }, critical: newWPDCriticalQueue()}
	// A closed/revoked callback cannot dereference this invalid payload pointer.
	r := wpdEventRecord{UserData: 1, UserDataLength: 4096}
	b.record(&r)
	if b.data.CaptureDenied != 1 || b.critical.snapshot().Seen != 0 {
		t.Fatal(b.data.CaptureDenied, b.critical.snapshot())
	}
}
func TestWPDProjectionABI(t *testing.T) {
	if unsafe.Offsetof(wpdProjectionRecordView{}.Data) != 96 || unsafe.Sizeof(wpdProjectionRecordView{}) != unsafe.Sizeof(wpdEventRecord{}) {
		t.Fatal("borrowed record ABI")
	}
	// Scalar parser reads unsigned values, preserving zero success values.
	b := wpdProjectionFixture(2001)
	binary.LittleEndian.PutUint32(b[18:], 0)
	binary.LittleEndian.PutUint16(b[22:], 0)
	_, r, s := wpdProjectMTP(2001, uint16(len(b)), func(off, size int) uint64 {
		if size == 2 {
			return uint64(binary.LittleEndian.Uint16(b[off:]))
		}
		return uint64(binary.LittleEndian.Uint32(b[off:]))
	})
	if s != "decoded" || !r.CodeRead || !r.TransportRead || r.Code != 0 || r.TransportHR != 0 {
		t.Fatal(r, s)
	}
}
