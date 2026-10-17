//go:build windows && amd64

package ipadncm

import (
	"testing"
	"unsafe"
)

// The portable query parser refuses string offsets within these native headers.
var _ [120 - unsafe.Sizeof(wpdTraceProperties{})]byte
var _ [unsafe.Sizeof(wpdTraceProperties{}) - 120]byte
var _ [48 - unsafe.Sizeof(wpdWnode{})]byte
var _ [unsafe.Sizeof(wpdWnode{}) - 48]byte
var _ [112 - unsafe.Offsetof(wpdTraceProperties{}.LogFileNameOffset)]byte
var _ [unsafe.Offsetof(wpdTraceProperties{}.LogFileNameOffset) - 112]byte

func TestWPDNativeQueryBufferDoesNotEchoExpectedIdentity(t *testing.T) {
	j := cleanupWPDMetadataFixture()
	b, err := wpdQueryProperties(j)
	if err != nil || b.Name != ([1024]uint16{}) || b.Path != ([1024]uint16{}) || b.Properties.LoggerNameOffset != 120 || b.Properties.LogFileNameOffset != 2168 {
		t.Fatal(b, err)
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(b)), int(unsafe.Sizeof(*b)))
	d := wpdCheckSessionQuery(j, "", raw, true, 0x10000100, 0, b.Properties.LoggerNameOffset, b.Properties.LogFileNameOffset)
	if d.Mismatch != 4 {
		t.Fatal("unwritten output falsely proves identity", d)
	}
}
