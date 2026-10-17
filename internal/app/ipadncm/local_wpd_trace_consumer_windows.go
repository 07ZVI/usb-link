//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"runtime"
	"sync"
	"unsafe"
)

var wpdOpenTrace = windows.NewLazySystemDLL("advapi32.dll").NewProc("OpenTraceW")
var wpdProcessTrace = windows.NewLazySystemDLL("advapi32.dll").NewProc("ProcessTrace")
var wpdCloseTrace = windows.NewLazySystemDLL("advapi32.dll").NewProc("CloseTrace")
var wpdEventInformation = windows.NewLazySystemDLL("tdh.dll").NewProc("TdhGetEventInformation")
var wpdGetPropertySize = windows.NewLazySystemDLL("tdh.dll").NewProc("TdhGetPropertySize")
var wpdGetProperty = windows.NewLazySystemDLL("tdh.dll").NewProc("TdhGetProperty")
var wpdManifestEvents = windows.NewLazySystemDLL("tdh.dll").NewProc("TdhEnumerateManifestProviderEvents")
var wpdManifestInformation = windows.NewLazySystemDLL("tdh.dll").NewProc("TdhGetManifestEventInformation")

// This path accepts only installed-provider identities and descriptors. It
// cannot read event payloads: no EVENT_RECORD is supplied to either TDH API.
func readWPDManifestTemplates(catalog [3]wpdTraceCatalogEntry, allowed func() bool) wpdManifestTemplates {
	var out wpdManifestTemplates
	for i, target := range wpdManifestTargets {
		d := wpdManifestTemplate{Provider: wpdProviderLabels[target.Provider], EventID: target.ID, Source: wpdManifestSource}
		out[i] = d
		if !allowed() {
			out[i].Stage = "cancelled"
			continue
		}
		entry := catalog[target.Provider]
		if !entry.Found || entry.Schema != "manifest" {
			out[i].Stage = "provider_unavailable"
			continue
		}
		guid := *(*windows.GUID)(unsafe.Pointer(&entry.GUID[0]))
		read := func(proc *windows.LazyProc, descriptor *[16]byte, kind string) ([]byte, string, uint32) {
			if !allowed() {
				return nil, "cancelled", 0
			}
			var size uint32
			call := func(buffer uintptr) uintptr {
				if descriptor == nil {
					r, _, _ := proc.Call(uintptr(unsafe.Pointer(&guid)), buffer, uintptr(unsafe.Pointer(&size)))
					return r
				}
				r, _, _ := proc.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&descriptor[0])), buffer, uintptr(unsafe.Pointer(&size)))
				return r
			}
			r := call(0)
			if r != 122 {
				return nil, kind + "_size_failed", uint32(r)
			}
			minimum := uint32(8)
			if descriptor != nil {
				minimum = 112
			}
			if size < minimum || size > 65536 {
				return nil, kind + "_invalid", 0
			}
			if !allowed() {
				return nil, "cancelled", 0
			}
			buf := make([]byte, size)
			r = call(uintptr(unsafe.Pointer(&buf[0])))
			runtime.KeepAlive(buf)
			if r != 0 {
				return nil, kind + "_read_failed", uint32(r)
			}
			if size < minimum || uint64(size) > uint64(len(buf)) {
				return nil, kind + "_invalid", 0
			}
			return buf[:size], "", 0
		}
		buf, stage, code := read(wpdManifestEvents, nil, "enumeration")
		if stage != "" {
			out[i].Stage, out[i].NativeCode = stage, code
			continue
		}
		descriptor, stage := wpdManifestDescriptor(buf, target.ID)
		if stage != "" {
			out[i].Stage = stage
			continue
		}
		buf, stage, code = read(wpdManifestInformation, &descriptor, "metadata")
		if stage != "" {
			out[i].Stage, out[i].NativeCode = stage, code
			continue
		}
		var returnedGUID [16]byte
		copy(returnedGUID[:], buf[:16])
		var returnedDescriptor [16]byte
		copy(returnedDescriptor[:], buf[32:48])
		if returnedGUID != entry.GUID || returnedDescriptor != descriptor {
			out[i].Stage = "identity_mismatch"
			continue
		}
		out[i].Fields, out[i].Properties, out[i].Top, out[i].Stage = wpdManifestDefinition(buf)
		out[i].Complete = out[i].Stage == "complete"
	}
	return out
}

type wpdEventDescriptor struct {
	ID                              uint16
	Version, Channel, Level, Opcode uint8
	Task                            uint16
	Keyword                         uint64
}
type wpdEventHeader struct {
	Size, HeaderType, Flags, EventProperty uint16
	ThreadID, ProcessID                    uint32
	Timestamp                              int64
	Provider                               windows.GUID
	Descriptor                             wpdEventDescriptor
	KernelTime, UserTime                   uint32
	Activity                               windows.GUID
}
type wpdEventRecord struct {
	Header                              wpdEventHeader
	BufferContext                       uint32
	ExtendedDataCount, UserDataLength   uint16
	ExtendedData, UserData, UserContext uintptr
}
type wpdLogfile struct {
	LogFileName, LoggerName        *uint16
	CurrentTime                    int64
	BuffersRead, Mode              uint32
	CurrentEvent                   [88]byte
	LogfileHeader                  [280]byte
	BufferCallback                 uintptr
	BufferSize, Filled, EventsLost uint32
	EventRecordCallback            uintptr
	IsKernelTrace                  uint32
	Context                        uintptr
}

var wpdConsumers = struct {
	sync.Mutex
	next  uintptr
	items map[uintptr]*localWPDTraceNative
}{items: map[uintptr]*localWPDTraceNative{}}
var wpdEventCallback = windows.NewCallback(func(r *wpdEventRecord) uintptr {
	if r == nil {
		return 0
	}
	wpdConsumers.Lock()
	b := wpdConsumers.items[r.UserContext]
	wpdConsumers.Unlock()
	if b != nil {
		b.record(r)
	}
	return 0
})

func (b *localWPDTraceNative) openConsumer() error {
	name, e := windows.UTF16PtrFromString(b.journal.Session)
	if e != nil {
		return wpdTraceError("WPD_TRACE_NAME_INVALID", 0)
	}
	wpdConsumers.Lock()
	wpdConsumers.next++
	key := wpdConsumers.next
	wpdConsumers.items[key] = b
	wpdConsumers.Unlock()
	b.consumerKey = key
	log := &wpdLogfile{LoggerName: name, Mode: 0x100 | 0x10000000, EventRecordCallback: wpdEventCallback, Context: key}
	h, _, last := wpdOpenTrace.Call(uintptr(unsafe.Pointer(log)))
	if h == ^uintptr(0) {
		wpdConsumers.Lock()
		delete(wpdConsumers.items, key)
		wpdConsumers.Unlock()
		b.consumerKey = 0
		return wpdTraceError("WPD_TRACE_CONSUMER_OPEN_FAILED", wpdNativeCode(last))
	}
	b.consumer = uint64(h)
	b.startCriticalConsumer()
	b.startSummaryConsumer()
	b.consumerDone = make(chan struct{})
	done := b.consumerDone
	handle := uint64(h)
	go func() {
		r, _, _ := wpdProcessTrace.Call(uintptr(unsafe.Pointer(&handle)), 1, 0, 0)
		b.mu.Lock()
		if r != 0 && r != 1223 {
			b.consumerError = uint32(r)
		}
		b.mu.Unlock()
		runtime.KeepAlive(log)
		close(done)
	}()
	return nil
}
func (b *localWPDTraceNative) closeConsumer() {
	if b.consumer != 0 {
		wpdCloseTrace.Call(uintptr(b.consumer))
		<-b.consumerDone
		b.consumer = 0
		b.consumerDone = nil
	}
	b.closeCriticalConsumer()
	b.closeSummaryConsumer()
	if b.consumerKey != 0 {
		wpdConsumers.Lock()
		delete(wpdConsumers.items, b.consumerKey)
		wpdConsumers.Unlock()
		b.consumerKey = 0
	}
}
func wpdEventMetadata(event *wpdEventRecord) ([]byte, string, uint32) {
	var size uint32
	r, _, _ := wpdEventInformation.Call(uintptr(unsafe.Pointer(event)), 0, 0, 0, uintptr(unsafe.Pointer(&size)))
	if r != 122 {
		return nil, "metadata_size_failed", uint32(r)
	}
	if size < 112 || size > 65536 {
		return nil, "metadata_invalid", 0
	}
	metadata := make([]byte, size)
	r, _, _ = wpdEventInformation.Call(uintptr(unsafe.Pointer(event)), 0, 0, uintptr(unsafe.Pointer(&metadata[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return nil, "metadata_read_failed", uint32(r)
	}
	if size < 112 || uint64(size) > uint64(len(metadata)) {
		return nil, "metadata_invalid", 0
	}
	return metadata[:size], "", 0
}
func wpdDecodeCommand(event *wpdEventRecord, metadata []byte, stage string, code uint32, trustedMTP bool) (string, uint64, localWPDTraceSchema, wpdMTPResponse) {
	d := localWPDTraceSchema{EventID: event.Header.Descriptor.ID, Version: event.Header.Descriptor.Version, HeaderFlags: event.Header.Flags, DataLength: event.UserDataLength, Stage: stage, NativeCode: code}
	if stage != "" {
		return "", 0, d, wpdMTPResponse{}
	}
	fields, info, valid := wpdTraceInspectMetadata(metadata)
	d.localWPDTraceSchemaInfo = info
	if !valid {
		d.Stage = "metadata_invalid"
		return "", 0, d, wpdMTPResponse{}
	}
	strictResponse := false
	if trustedMTP {
		if exact := wpdExactMTPCommandField("mtp", event.Header.Descriptor.ID, event.Header.Descriptor.Version, metadata); len(exact) > 0 {
			fields = append(fields, exact...)
			strictResponse = event.Header.Descriptor.ID == 2001
			d.Candidates++
			if d.OtherNames > 0 {
				d.OtherNames--
			}
		}
	}
	descriptor := func(field string) (*uint16, *wpdPropertyDescriptor) {
		name, _ := windows.UTF16PtrFromString(field)
		return name, &wpdPropertyDescriptor{Name: uint64(uintptr(unsafe.Pointer(name))), ArrayIndex: 0xffffffff}
	}
	field, value, result, native, response := wpdDecodeCommandValues(fields, strictResponse, func(field string) (uint32, uint32) {
		name, p := descriptor(field)
		var n uint32
		r, _, _ := wpdGetPropertySize.Call(uintptr(unsafe.Pointer(event)), 0, 0, 1, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&n)))
		runtime.KeepAlive(name)
		return n, uint32(r)
	}, func(field string, n uint32) (uint64, uint32) {
		name, p := descriptor(field)
		var value [8]byte
		r, _, _ := wpdGetProperty.Call(uintptr(unsafe.Pointer(event)), 0, 0, 1, uintptr(unsafe.Pointer(p)), uintptr(n), uintptr(unsafe.Pointer(&value[0])))
		runtime.KeepAlive(name)
		return binary.LittleEndian.Uint64(value[:]), uint32(r)
	})
	d.Stage, d.NativeCode = result, native
	return field, value, d, response
}

type wpdPropertyDescriptor struct {
	Name                 uint64
	ArrayIndex, Reserved uint32
}
