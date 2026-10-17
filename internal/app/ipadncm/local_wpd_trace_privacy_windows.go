//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

type wpdMetadataFilterDescriptor struct {
	Ptr        uint64
	Size, Type uint32
}
type wpdMetadataEnableParameters struct {
	Version, EnableProperty, ControlFlags uint32
	SourceID                              windows.GUID
	Filter                                *wpdMetadataFilterDescriptor
	Count                                 uint32
}

func readWPDSafeEventIDs(entry wpdTraceCatalogEntry, label string, allowed func() bool) []uint16 {
	if !entry.Found || entry.Schema != "manifest" {
		return nil
	}
	guid := *(*windows.GUID)(unsafe.Pointer(&entry.GUID[0]))
	read := func(d *[16]byte) []byte {
		if !allowed() {
			return nil
		}
		var size uint32
		call := func(p uintptr) uintptr {
			if d == nil {
				r, _, _ := wpdManifestEvents.Call(uintptr(unsafe.Pointer(&guid)), p, uintptr(unsafe.Pointer(&size)))
				return r
			}
			r, _, _ := wpdManifestInformation.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&d[0])), p, uintptr(unsafe.Pointer(&size)))
			return r
		}
		if call(0) != 122 || size < 8 || size > 65536 {
			return nil
		}
		b := make([]byte, size)
		if !allowed() || call(uintptr(unsafe.Pointer(&b[0]))) != 0 || size < 8 || uint64(size) > uint64(len(b)) {
			return nil
		}
		runtime.KeepAlive(b)
		b = b[:size]
		if d != nil && (len(b) < 112 || *(*windows.GUID)(unsafe.Pointer(&b[0])) != guid) {
			return nil
		}
		return b
	}
	return wpdSafeEventIDs(label, read(nil), func(d [16]byte) []byte { return read(&d) })
}

func readWPDProjectionDefinitions(entry wpdTraceCatalogEntry, label string, allowed func() bool) []wpdProjectionDefinition {
	if !entry.Found || entry.Schema != "manifest" {
		return nil
	}
	guid := *(*windows.GUID)(unsafe.Pointer(&entry.GUID[0]))
	read := func(d *[16]byte) []byte {
		if !allowed() {
			return nil
		}
		var size uint32
		call := func(p uintptr) uintptr {
			if d == nil {
				r, _, _ := wpdManifestEvents.Call(uintptr(unsafe.Pointer(&guid)), p, uintptr(unsafe.Pointer(&size)))
				return r
			}
			r, _, _ := wpdManifestInformation.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&d[0])), p, uintptr(unsafe.Pointer(&size)))
			return r
		}
		if call(0) != 122 || size < 8 || size > 65536 {
			return nil
		}
		b := make([]byte, size)
		if !allowed() || call(uintptr(unsafe.Pointer(&b[0]))) != 0 || size < 8 || uint64(size) > uint64(len(b)) {
			return nil
		}
		runtime.KeepAlive(b)
		b = b[:size]
		if d != nil && (len(b) < 112 || *(*windows.GUID)(unsafe.Pointer(&b[0])) != guid) {
			return nil
		}
		return b
	}
	return wpdProjectionDefinitions(label, read(nil), func(d [16]byte) []byte { return read(&d) })
}

func enableWPDMetadataEvents(handle uint64, provider windows.GUID, ids []uint16) uint32 {
	return wpdMetadataEnableCall(ids, func(p *wpdMetadataEnableParameters, _ []byte) uint32 {
		r, _, _ := wpdEnableTrace.Call(uintptr(handle), uintptr(unsafe.Pointer(&provider)), 1, 5, ^uintptr(0), 0, 1000, uintptr(unsafe.Pointer(p)))
		return uint32(r)
	})
}

func wpdMetadataEnableCall(ids []uint16, call func(*wpdMetadataEnableParameters, []byte) uint32) uint32 {
	filter := wpdEventIDFilter(ids)
	if len(filter) == 0 {
		return 87
	}
	d := wpdMetadataFilterDescriptor{Ptr: uint64(uintptr(unsafe.Pointer(&filter[0]))), Size: uint32(len(filter)), Type: 0x80000200}
	p := wpdMetadataEnableParameters{Version: 2, Filter: &d, Count: 1}
	var pin runtime.Pinner
	pin.Pin(&filter[0])
	pin.Pin(&d)
	pin.Pin(&p)
	defer pin.Unpin()
	r := call(&p, filter)
	runtime.KeepAlive(filter)
	runtime.KeepAlive(d)
	runtime.KeepAlive(p)
	return r
}

func wpdMetadataProperties(j localWPDTraceJournal) (*wpdTracePropertyBuffer, error) {
	if !j.valid() || j.Schema != 2 {
		return nil, wpdTraceError("WPD_TRACE_JOURNAL_INVALID", 0)
	}
	p, e := wpdProperties(j, "")
	if e != nil {
		return nil, e
	}
	p.Properties.BufferSize = 64
	p.Properties.MinimumBuffers = 4
	p.Properties.MaximumBuffers = 16
	p.Properties.LogFileMode = wpdMetadataBaseMode | wpdStopOnHybridShutdown
	p.Properties.FlushTimer = 1
	return p, nil
}
