//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"testing"
	"unsafe"
)

func TestUSBTraceFilterABI(t *testing.T) {
	if unsafe.Sizeof(usbTraceFilterDescriptor{}) != 16 || unsafe.Sizeof(usbTraceEnableParameters{}) != 48 || unsafe.Offsetof(usbTraceEnableParameters{}.Filter) != 32 || unsafe.Offsetof(usbTraceIDFilter{}.IDs) != 4 {
		t.Fatal("filter ABI")
	}
}

func TestUSBTraceBorrowedRecordABI(t *testing.T) {
	if unsafe.Sizeof(usbTraceRecordView{}) != unsafe.Sizeof(wpdEventRecord{}) || unsafe.Offsetof(usbTraceRecordView{}.Data) != unsafe.Offsetof(wpdEventRecord{}.UserData) || unsafe.Offsetof(usbTraceRecordView{}.UserContext) != unsafe.Offsetof(wpdEventRecord{}.UserContext) {
		t.Fatal("record view ABI")
	}
}
func TestUSBTraceNoFileProperties(t *testing.T) {
	j := usbTraceJournal{Schema: 1, Name: "USBLink-USBMetadata-0123456789abcdef0123456789abcdef", GUID: "{11111111-1111-1111-1111-111111111111}"}
	if !j.valid() {
		t.Fatal("fixture")
	}
	p := usbTraceProperties(j)
	if p.Properties.LogFileMode != 0x00400100 || p.Properties.LogFileNameOffset != 0 || p.Properties.MaximumFileSize != 0 {
		t.Fatal("raw file configuration")
	}
	j.GUID = "{00000000-0000-0000-0000-000000000000}"
	if j.valid() {
		t.Fatal("zero ownership GUID")
	}
}

func TestUSBTraceQueryPropertiesABIAndOutputBuffers(t *testing.T) {
	if unsafe.Sizeof(wpdWnode{}) != 48 || unsafe.Sizeof(wpdTraceProperties{}) != 120 || unsafe.Offsetof(wpdTraceProperties{}.LogFileNameOffset) != 112 || unsafe.Offsetof(wpdTraceProperties{}.LoggerNameOffset) != 116 {
		t.Fatal("EVENT_TRACE_PROPERTIES ABI")
	}
	j := usbTraceJournal{Schema: 1, Name: "USBLink-USBMetadata-0123456789abcdef0123456789abcdef", GUID: "{11111111-1111-1111-1111-111111111111}"}
	b := usbTraceQueryProperties(j)
	if b.Properties.LogFileMode != 0 || b.Properties.LoggerNameOffset != 120 || b.Properties.LogFileNameOffset != 2168 || b.Name[0] != 0 || b.Path[0] != 0 {
		t.Fatal("query must reserve zeroed output buffers")
	}
	if usbTraceProperties(j).Properties.LogFileNameOffset != 0 {
		t.Fatal("query changed start policy")
	}
}
