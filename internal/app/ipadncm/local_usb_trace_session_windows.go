//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func usbTraceProperties(j usbTraceJournal) *wpdTracePropertyBuffer {
	b := new(wpdTracePropertyBuffer)
	b.Properties.Wnode.Size = uint32(unsafe.Sizeof(*b))
	b.Properties.Wnode.GUID, _ = windows.GUIDFromString(j.GUID)
	b.Properties.Wnode.Flags = 0x20000
	b.Properties.Wnode.ClientContext = 1
	b.Properties.LoggerNameOffset = uint32(unsafe.Offsetof(b.Name))
	copy(b.Name[:], windows.StringToUTF16(j.Name))
	// No log filename. Event-ID filtering still requires the entire template
	// to be safe because Windows may internally back a real-time session.
	b.Properties.LogFileMode = usbTraceRealtimeMode | usbTraceStopOnHybridShutdown
	b.Properties.BufferSize = 64
	b.Properties.MinimumBuffers = 4
	b.Properties.MaximumBuffers = 16
	b.Properties.FlushTimer = 1
	return b
}
