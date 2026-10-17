//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"
)

var _ [48 - unsafe.Sizeof(wpdMetadataEnableParameters{})]byte
var _ [unsafe.Sizeof(wpdMetadataEnableParameters{}) - 48]byte
var _ [32 - unsafe.Offsetof(wpdMetadataEnableParameters{}.Filter)]byte
var _ [unsafe.Offsetof(wpdMetadataEnableParameters{}.Filter) - 32]byte
var _ [16 - unsafe.Sizeof(wpdMetadataFilterDescriptor{})]byte
var _ [unsafe.Sizeof(wpdMetadataFilterDescriptor{}) - 16]byte

func TestWPDMetadataPropertiesNeverNameAnOutputFile(t *testing.T) {
	j := localWPDTraceJournal{Schema: 2, Mode: "metadata_session", Session: "USBLink-WPD-" + strings.Repeat("a", 32), GUID: "{12345678-1234-1234-1234-123456789abc}", OwnerSID: "S-1-5-18"}
	start, e := wpdMetadataProperties(j)
	if e != nil || start.Properties.LogFileNameOffset != 0 || start.Properties.MaximumFileSize != 0 || start.Properties.LogFileMode != 0x10400100 {
		t.Fatal("file session configured", e)
	}
	p, e := wpdProperties(j, `C:\private\must-not-write.etl`)
	if e != nil || p.Properties.LogFileNameOffset != 0 || p.Path != ([1024]uint16{}) {
		t.Fatal(p, e)
	}
	j.Schema = 1
	j.Mode = ""
	j.File = localWPDTraceETLFile
	p, e = wpdProperties(j, `C:\private\legacy.etl`)
	if e != nil || p.Properties.LogFileNameOffset == 0 || p.Path[0] != 'C' {
		t.Fatal("legacy recovery props", e)
	}
}

func TestWPDMetadataNativeEnableParameters(t *testing.T) {
	calls := 0
	call := func(p *wpdMetadataEnableParameters, b []byte) uint32 {
		calls++
		if p.Version != 2 || p.Count != 1 || p.EnableProperty != 0 || p.ControlFlags != 0 || p.Filter == nil || p.Filter.Type != 0x80000200 || p.Filter.Size != 6 {
			t.Fatal(p)
		}
		// Only inspect the buffer while the production wrapper keeps it alive.
		if p.Filter.Ptr != uint64(uintptr(unsafe.Pointer(&b[0]))) || len(b) != int(p.Filter.Size) {
			t.Fatal("wrong native buffer")
		}
		if b[0] != 1 || b[1] != 0 || binary.LittleEndian.Uint16(b[2:]) != 1 || binary.LittleEndian.Uint16(b[4:]) != 2000 {
			t.Fatal(b)
		}
		return 5
	}
	if wpdMetadataEnableCall([]uint16{2000}, call) != 5 || calls != 1 {
		t.Fatal("native failure hidden")
	}
	if wpdMetadataEnableCall(nil, call) != 87 || calls != 1 {
		t.Fatal("unfiltered enable")
	}
}

func TestWPDMetadataConsumerCloseWithoutSessionDoesNotTouchETW(t *testing.T) {
	b := &localWPDTraceNative{}
	b.closeConsumer()
	b.closeConsumer()
	if b.consumerKey != 0 || b.consumer != 0 || b.consumerDone != nil {
		t.Fatal("consumer retained")
	}
}
