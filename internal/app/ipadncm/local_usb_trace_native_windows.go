//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var usbTraceKeywordInformation = windows.NewLazySystemDLL("tdh.dll").NewProc("TdhEnumerateProviderFieldInformation")
var usbTraceProviderNames = [3]string{"Microsoft-Windows-USB-USBHUB3", "Microsoft-Windows-USB-UCX", "Microsoft-Windows-USB-USBXHCI"}

// ProcessTrace delivers its own synthetic events even for a real-time session.
// Event ID zero alone is not evidence that a callback is session metadata.
var usbTraceSessionMetadataGUID = windows.GUID{Data1: 0x68fdd900, Data2: 0x4a3e, Data3: 0x11d1, Data4: [8]byte{0x84, 0xf4, 0, 0, 0xf8, 0x04, 0x64, 0xe3}}

type usbTraceFilterDescriptor struct {
	Ptr        uint64
	Size, Type uint32
}
type usbTraceEnableParameters struct {
	Version, Property, Control uint32
	Source                     windows.GUID
	Filter                     *usbTraceFilterDescriptor
	Count                      uint32
}
type usbTraceIDFilter struct {
	FilterIn, Reserved uint8
	Count              uint16
	IDs                [64]uint16
}
type usbTraceNativeProvider struct {
	guid     windows.GUID
	ids      []uint16
	schemas  []usbTraceSchema
	keywords uint64
}
type usbTraceNative struct {
	stopResult usbTraceStopResult
	ctx        context.Context
	revoked    atomic.Bool
	dir        string
	journal    usbTraceJournal
	lease      windows.Handle
	handle     uint64
	consumer   uint64
	key        uintptr
	done       chan struct{}
	workerDone chan struct{}
	queue      chan usbTraceEvent
	providers  [3]usbTraceNativeProvider
	admission  atomic.Bool
	failed     atomic.Bool
	terminated atomic.Bool
	stopping   atomic.Bool
	start      time.Time
}

var localUSBTrace = struct {
	sync.Mutex
	status    usbTraceStatus
	requested bool
	running   bool
	native    *usbTraceNative
	wake      chan struct{}
}{status: newUSBTraceStatus(), wake: make(chan struct{}, 1)}
var usbTraceConsumers = struct {
	sync.Mutex
	next  uintptr
	items map[uintptr]*usbTraceNative
}{items: map[uintptr]*usbTraceNative{}}

func SetLocalUSBTraceMaster(on bool) {
	localUSBTrace.Lock()
	localUSBTrace.requested = on
	localUSBTrace.status.Requested = on
	if !on && localUSBTrace.native != nil {
		localUSBTrace.native.admission.Store(false)
		localUSBTrace.native.revoked.Store(true)
		localUSBTrace.status.Active = false
		localUSBTrace.status.Phase = "stopping"
	}
	localUSBTrace.Unlock()
	select {
	case localUSBTrace.wake <- struct{}{}:
	default:
	}
}
func LocalUSBTraceDiagnostics() any {
	localUSBTrace.Lock()
	defer localUSBTrace.Unlock()
	s := localUSBTrace.status
	s.QueryOwnership, s.FirstQueryFailure = usbTraceQuerySnapshot()
	return s
}
func usbTraceStatusFailure(code string) {
	if !strings.HasPrefix(code, "USB_TRACE_") || len(code) > 64 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") != "" {
		code = "USB_TRACE_OPERATION_FAILED"
	}
	localUSBTrace.Lock()
	localUSBTrace.status.Error = code
	localUSBTrace.status.Coverage = "incomplete"
	localUSBTrace.status.Phase = "error"
	localUSBTrace.status.Active = false
	if code == "USB_TRACE_RECOVERY_FAILED" {
		localUSBTrace.status.RecoveryPending = true
		localUSBTrace.status.Phase = "recovery_pending"
	}
	if code == "USB_TRACE_NO_SAFE_EVENT_SCHEMA" {
		localUSBTrace.status.Coverage = "not_covered"
		localUSBTrace.status.Phase = "no_safe_event_schema"
	}
	localUSBTrace.Unlock()
}
func StartLocalUSBTrace(ctx context.Context, dir string) func() {
	localUSBTrace.Lock()
	if localUSBTrace.running {
		localUSBTrace.Unlock()
		return func() {}
	}
	localUSBTrace.running = true
	localUSBTrace.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { localUSBTrace.Lock(); localUSBTrace.running = false; localUSBTrace.Unlock() }()
		attempted := false
		var b *usbTraceNative
		if e := RestoreLocalUSBTrace(dir); e != nil {
			usbTraceStatusFailure("USB_TRACE_RECOVERY_FAILED")
			return
		}
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		defer func() {
			if b != nil {
				if e := b.stop(); e != nil {
					usbTraceStatusFailure("USB_TRACE_RECOVERY_FAILED")
				}
			}
			localUSBTrace.Lock()
			localUSBTrace.native = nil
			localUSBTrace.Unlock()
		}()
		for {
			if ctx.Err() != nil {
				return
			}
			if b != nil && b.failed.Load() {
				if e := b.stop(); e != nil {
					usbTraceStatusFailure("USB_TRACE_RECOVERY_FAILED")
					return
				}
				b = nil
				localUSBTrace.Lock()
				localUSBTrace.native = nil
				localUSBTrace.Unlock()
			}
			localUSBTrace.Lock()
			on := localUSBTrace.requested
			localUSBTrace.Unlock()
			if b != nil && (!on || b.revoked.Load()) {
				if e := b.stop(); e != nil {
					usbTraceStatusFailure(e.Error())
					return
				}
				b = nil
				attempted = false
				localUSBTrace.Lock()
				localUSBTrace.native = nil
				localUSBTrace.status.Phase = "disabled"
				localUSBTrace.Unlock()
			}
			if !on {
				attempted = false
			}
			if on && !attempted {
				attempted = true
				b = &usbTraceNative{dir: dir, start: time.Now(), ctx: ctx}
				localUSBTrace.Lock()
				localUSBTrace.status = newUSBTraceStatus()
				usbTraceResetQueries()
				localUSBTrace.status.Requested = localUSBTrace.requested
				localUSBTrace.status.Phase = "discovering"
				localUSBTrace.native = b
				localUSBTrace.Unlock()
				allowed := func() bool {
					localUSBTrace.Lock()
					defer localUSBTrace.Unlock()
					return ctx.Err() == nil && localUSBTrace.requested
				}
				if e := b.startCapture(allowed); e != nil {
					usbTraceStatusFailure(e.Error())
					if stopErr := b.stop(); stopErr != nil {
						usbTraceStatusFailure(stopErr.Error())
						return
					}
					if b.revoked.Load() {
						attempted = false
					}
					b = nil
					localUSBTrace.Lock()
					localUSBTrace.native = nil
					localUSBTrace.Unlock()
				}
			}
			if b != nil {
				b.sample()
			}
			RecordConnectionArchiveEvent("usb_native_trace_status", LocalUSBTraceDiagnostics())
			select {
			case <-ctx.Done():
				return
			case <-localUSBTrace.wake:
			case <-tick.C:
			}
		}
	}()
	return func() {
		cancel()
		localUSBTrace.Lock()
		if localUSBTrace.native != nil {
			localUSBTrace.native.admission.Store(false)
		}
		localUSBTrace.Unlock()
		<-done
	}
}

func usbTraceTDH(proc *windows.LazyProc, g *windows.GUID, descriptor *[16]byte) ([]byte, error) {
	var size uint32
	call := func(p uintptr) uintptr {
		var r uintptr
		if descriptor == nil {
			r, _, _ = proc.Call(uintptr(unsafe.Pointer(g)), p, uintptr(unsafe.Pointer(&size)))
		} else {
			r, _, _ = proc.Call(uintptr(unsafe.Pointer(g)), uintptr(unsafe.Pointer(&descriptor[0])), p, uintptr(unsafe.Pointer(&size)))
		}
		return r
	}
	if call(0) != 122 || size < 8 || size > 65536 {
		return nil, errors.New("USB_TRACE_METADATA_UNAVAILABLE")
	}
	buf := make([]byte, size)
	if call(uintptr(unsafe.Pointer(&buf[0]))) != 0 || size < 8 || int(size) > len(buf) {
		return nil, errors.New("USB_TRACE_METADATA_UNAVAILABLE")
	}
	runtime.KeepAlive(buf)
	return buf[:size], nil
}
func usbTraceForbiddenKeywords(g *windows.GUID) (uint64, error) {
	var size uint32
	call := func(p uintptr) uintptr {
		r, _, _ := usbTraceKeywordInformation.Call(uintptr(unsafe.Pointer(g)), 0, p, uintptr(unsafe.Pointer(&size)))
		return r
	}
	if call(0) != 122 || size < 8 || size > 65536 {
		return 0, errors.New("USB_TRACE_KEYWORDS_UNAVAILABLE")
	}
	buf := make([]byte, size)
	if call(uintptr(unsafe.Pointer(&buf[0]))) != 0 || size < 8 || int(size) > len(buf) {
		return 0, errors.New("USB_TRACE_KEYWORDS_UNAVAILABLE")
	}
	buf = buf[:size]
	n := binary.LittleEndian.Uint32(buf)
	if uint64(n)*16+8 > uint64(len(buf)) {
		return 0, errors.New("USB_TRACE_KEYWORDS_UNAVAILABLE")
	}
	var forbidden uint64
	found := 0
	for i := uint32(0); i < n; i++ {
		v := buf[8+i*16:]
		offset := binary.LittleEndian.Uint32(v)
		if uint64(offset) < 8+uint64(n)*16 {
			return 0, errors.New("USB_TRACE_KEYWORDS_UNAVAILABLE")
		}
		name := wpdTraceUTF16(buf, offset, 128)
		if name == "FullDataBusTrace" || name == "PartialDataBusTrace" {
			if binary.LittleEndian.Uint64(v[8:]) == 0 {
				return 0, errors.New("USB_TRACE_KEYWORDS_UNPROVEN")
			}
			forbidden |= binary.LittleEndian.Uint64(v[8:])
			found++
		}
	}
	if found != 2 || forbidden == 0 {
		return 0, errors.New("USB_TRACE_KEYWORDS_UNPROVEN")
	}
	return forbidden, nil
}
func usbTraceDiscover(allowed func() bool) ([3]usbTraceNativeProvider, error) {
	var out [3]usbTraceNativeProvider
	var size uint32
	r, _, _ := wpdEnumerateProviders.Call(0, uintptr(unsafe.Pointer(&size)))
	if r != 122 || size < 8 || size > 4<<20 {
		return out, errors.New("USB_TRACE_CATALOG_UNAVAILABLE")
	}
	buf := make([]byte, size)
	r, _, _ = wpdEnumerateProviders.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 || size < 8 || int(size) > len(buf) {
		return out, errors.New("USB_TRACE_CATALOG_UNAVAILABLE")
	}
	buf = buf[:size]
	n := binary.LittleEndian.Uint32(buf)
	if uint64(n)*24+8 > uint64(len(buf)) {
		return out, errors.New("USB_TRACE_CATALOG_INVALID")
	}
	var found [3]int
	for i := uint32(0); i < n; i++ {
		v := buf[8+i*24:]
		name := wpdTraceUTF16(buf, binary.LittleEndian.Uint32(v[20:]), 128)
		for p, want := range usbTraceProviderNames {
			if name == want && binary.LittleEndian.Uint32(v[16:]) == 0 {
				found[p]++
				out[p].guid = *(*windows.GUID)(unsafe.Pointer(&v[0]))
			}
		}
	}
	for p := range out {
		status := usbTraceProviderStatus{Provider: newUSBTraceStatus().Providers[p].Provider}
		publish := func() { localUSBTrace.Lock(); localUSBTrace.status.Providers[p] = status; localUSBTrace.Unlock() }
		if found[p] != 1 || out[p].guid == (windows.GUID{}) {
			status.Code = "provider_unavailable_or_ambiguous"
			publish()
			continue
		}
		forbidden, e := usbTraceForbiddenKeywords(&out[p].guid)
		if e != nil {
			status.Code = "keyword_schema_unproven"
			publish()
			continue
		}
		list, e := usbTraceTDH(wpdManifestEvents, &out[p].guid, nil)
		if e != nil {
			status.Code = "enumeration_failed"
			publish()
			continue
		}
		count := binary.LittleEndian.Uint32(list)
		if count > 4096 || uint64(count)*16+8 != uint64(len(list)) {
			status.Code = "enumeration_invalid"
			publish()
			continue
		}
		bad := map[uint16]bool{}
		var candidates []usbTraceSchema
		for i := uint32(0); i < count; i++ {
			if !allowed() {
				return out, errors.New("USB_TRACE_CANCELLED")
			}
			var d [16]byte
			copy(d[:], list[8+i*16:8+(i+1)*16])
			id := binary.LittleEndian.Uint16(d[:])
			status.Enumerated++
			metadata, e := usbTraceTDH(wpdManifestInformation, &out[p].guid, &d)
			var s usbTraceSchema
			reason := "read_failed"
			if e == nil {
				s, reason = usbTraceSafeSchema(metadata, d, *(*[16]byte)(unsafe.Pointer(&out[p].guid)))
			}
			if reason != "" || binary.LittleEndian.Uint64(d[8:])&forbidden != 0 {
				bad[id] = true
				status.Rejected++
				continue
			}
			candidates = append(candidates, s)
		}
		out[p].ids, out[p].schemas = usbTraceSafeIDs(candidates, bad)
		status.Omitted = usbTraceOmittedIDs(candidates, bad, len(out[p].ids))
		for _, s := range out[p].schemas {
			out[p].keywords |= binary.LittleEndian.Uint64(s.Descriptor[8:])
		}
		if len(out[p].ids) > 0 && !usbTraceKeywordMaskSafe(out[p].keywords, forbidden) {
			status.Omitted += len(out[p].ids)
			out[p].ids = nil
			out[p].schemas = nil
			out[p].keywords = 0
			status.Code = "keyword_mask_unproven"
			publish()
			continue
		}
		status.SafeIDs = len(out[p].ids)
		if status.SafeIDs == 0 {
			status.Code = "no_safe_event_schema"
		}
		publish()
	}
	return out, nil
}

func (b *usbTraceNative) startCapture(allowed func() bool) error {
	providers, e := usbTraceDiscover(allowed)
	if e != nil {
		return e
	}
	b.providers = providers
	total := 0
	for _, p := range providers {
		total += len(p.ids)
	}
	if total == 0 {
		return errors.New("USB_TRACE_NO_SAFE_EVENT_SCHEMA")
	}
	if !allowed() {
		return errors.New("USB_TRACE_CANCELLED")
	}
	b.lease, e = usbTraceLease(b.dir)
	if e != nil {
		return e
	}
	if e = usbTraceRestoreLocked(b.dir); e != nil {
		return e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return errors.New("USB_TRACE_RANDOM_FAILED")
	}
	g, e := windows.GenerateGUID()
	if e != nil {
		return errors.New("USB_TRACE_RANDOM_FAILED")
	}
	b.journal = usbTraceJournal{Schema: 1, Name: "USBLink-USBMetadata-" + hex.EncodeToString(nonce[:]), GUID: g.String()}
	if e = usbTraceWriteJournal(b.dir, b.journal); e != nil {
		return e
	}
	if !allowed() {
		return errors.New("USB_TRACE_CANCELLED")
	}
	props := usbTraceProperties(b.journal)
	name := windows.StringToUTF16Ptr(b.journal.Name)
	r, _, _ := wpdStartTrace.Call(uintptr(unsafe.Pointer(&b.handle)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(props)))
	if r != 0 {
		return errors.New("USB_TRACE_START_FAILED")
	}
	if _, found, e := usbTraceQuery(b.journal); e != nil || !found {
		return errors.New("USB_TRACE_START_UNCONFIRMED")
	}
	usbTraceConsumers.Lock()
	usbTraceConsumers.next++
	b.key = usbTraceConsumers.next
	usbTraceConsumers.items[b.key] = b
	usbTraceConsumers.Unlock()
	log := &wpdLogfile{LoggerName: name, Mode: 0x100 | 0x10000000, EventRecordCallback: usbTraceCallback, Context: b.key}
	h, _, _ := wpdOpenTrace.Call(uintptr(unsafe.Pointer(log)))
	if h == ^uintptr(0) {
		return errors.New("USB_TRACE_CONSUMER_FAILED")
	}
	b.consumer = uint64(h)
	b.queue = make(chan usbTraceEvent, 128)
	b.workerDone = make(chan struct{})
	go func() {
		defer close(b.workerDone)
		for e := range b.queue {
			accepted := RecordConnectionArchiveEventAccepted("usb_native_metadata", e)
			localUSBTrace.Lock()
			s := &localUSBTrace.status
			s.Accepted++
			if s.Coverage == "not_covered" {
				s.Coverage = "metadata_only"
			}
			s.LastEventUTC = e.ReceivedUTC
			if !accepted {
				s.ArchiveRejected++
			}
			if s.RecentCount == len(s.Recent) {
				copy(s.Recent[:], s.Recent[1:])
				s.RecentOmitted++
			} else {
				s.RecentCount++
			}
			s.Recent[s.RecentCount-1] = e
			localUSBTrace.Unlock()
		}
	}()
	b.done = make(chan struct{})
	go func() {
		defer close(b.done)
		wpdProcessTrace.Call(uintptr(unsafe.Pointer(&b.consumer)), 1, 0, 0)
		runtime.KeepAlive(log)
		localUSBTrace.Lock()
		b.terminated.Store(true)
		b.admission.Store(false)
		unexpected := !b.stopping.Load()
		if unexpected {
			b.failed.Store(true)
			localUSBTrace.status.Active = false
			localUSBTrace.status.Error = "USB_TRACE_CONSUMER_FAILED"
			localUSBTrace.status.Coverage = "incomplete"
			localUSBTrace.status.Phase = "error"
		}
		localUSBTrace.Unlock()
		if unexpected {
			select {
			case localUSBTrace.wake <- struct{}{}:
			default:
			}
		}
	}()
	localUSBTrace.Lock()
	admitted := usbTraceCanAdmit(localUSBTrace.requested, b.ctx.Err() == nil, b.terminated.Load(), b.stopping.Load() || b.revoked.Load())
	b.admission.Store(admitted)
	localUSBTrace.Unlock()
	if !admitted {
		return errors.New("USB_TRACE_CONSUMER_UNAVAILABLE")
	}
	for i, p := range b.providers {
		if len(p.ids) == 0 {
			continue
		}
		if !allowed() || b.terminated.Load() {
			b.admission.Store(false)
			return errors.New("USB_TRACE_CANCELLED")
		}
		filter := usbTraceIDFilter{FilterIn: 1, Count: uint16(len(p.ids))}
		copy(filter.IDs[:], p.ids)
		desc := usbTraceFilterDescriptor{Ptr: uint64(uintptr(unsafe.Pointer(&filter))), Size: uint32(4 + len(p.ids)*2), Type: 0x80000200}
		params := usbTraceEnableParameters{Version: 2, Filter: &desc, Count: 1}
		var pin runtime.Pinner
		pin.Pin(&filter)
		pin.Pin(&desc)
		pin.Pin(&params)
		r, _, _ := wpdEnableTrace.Call(uintptr(b.handle), uintptr(unsafe.Pointer(&p.guid)), 1, 5, uintptr(p.keywords), 0, 1000, uintptr(unsafe.Pointer(&params)))
		pin.Unpin()
		runtime.KeepAlive(filter)
		runtime.KeepAlive(desc)
		runtime.KeepAlive(params)
		if r != 0 {
			return errors.New("USB_TRACE_FILTER_ENABLE_FAILED")
		}
		localUSBTrace.Lock()
		localUSBTrace.status.Providers[i].Enabled = true
		localUSBTrace.Unlock()
	}
	if !allowed() {
		b.admission.Store(false)
		return errors.New("USB_TRACE_CANCELLED")
	}
	localUSBTrace.Lock()
	if usbTraceCanAdmit(localUSBTrace.requested, b.ctx.Err() == nil, b.terminated.Load(), b.stopping.Load() || b.revoked.Load()) {
		localUSBTrace.status.Active = true
		localUSBTrace.status.Phase = "metadata_only"
		localUSBTrace.status.Coverage = "not_covered"
		localUSBTrace.status.RunID = b.journal.Name[len("USBLink-USBMetadata-"):]
		localUSBTrace.status.StartedUTC = usbTraceUTC()
	} else {
		localUSBTrace.Unlock()
		return errors.New("USB_TRACE_CONSUMER_UNAVAILABLE")
	}
	localUSBTrace.Unlock()
	return nil
}

// EVENT_RECORD has pointer-sized fields at offsets 88, 96 and 104.
type usbTraceRecordView struct {
	Header                            wpdEventHeader
	BufferContext                     uint32
	ExtendedDataCount, UserDataLength uint16
	ExtendedData                      uintptr
	Data                              *byte
	UserContext                       uintptr
}

var usbTraceCallback = windows.NewCallback(consumeUSBTraceRecord)

func consumeUSBTraceRecord(r *wpdEventRecord) uintptr {
	if r == nil {
		return 0
	}
	usbTraceConsumers.Lock()
	b := usbTraceConsumers.items[r.UserContext]
	usbTraceConsumers.Unlock()
	if b == nil || !b.admission.Load() {
		return 0
	}
	localUSBTrace.Lock()
	defer localUSBTrace.Unlock()
	if !b.admission.Load() || !localUSBTrace.requested || b.ctx.Err() != nil || b.revoked.Load() {
		return 0
	}
	s := &localUSBTrace.status
	providerIndex := -1
	providerLabel := "other_provider"
	if r.Header.Provider == usbTraceSessionMetadataGUID {
		providerLabel = "session_metadata"
	} else {
		for i, provider := range b.providers {
			if provider.guid != (windows.GUID{}) && provider.guid == r.Header.Provider {
				providerIndex, providerLabel = i, s.Providers[i].Provider
				break
			}
		}
	}
	header := usbTraceCallbackHeader{Size: r.Header.Size, Flags: r.Header.Flags, ExtendedCount: r.ExtendedDataCount, DataLength: r.UserDataLength, ID: r.Header.Descriptor.ID, Version: r.Header.Descriptor.Version, Opcode: r.Header.Descriptor.Opcode, HasData: r.UserData != 0}
	if !s.admitHeader(providerLabel, header) {
		return 0
	}
	var d [16]byte
	copy(d[:], unsafe.Slice((*byte)(unsafe.Pointer(&r.Header.Descriptor)), 16))
	for p, provider := range b.providers {
		if p != providerIndex {
			continue
		}
		for _, schema := range provider.schemas {
			if schema.Descriptor != d {
				continue
			}
			var data []byte
			if r.UserDataLength > 0 {
				// Read the native pointer through an ABI-equivalent typed view; never
				// retain this borrowed callback memory after returning.
				data = unsafe.Slice((*usbTraceRecordView)(unsafe.Pointer(r)).Data, int(r.UserDataLength))
			}
			e, ok := usbTraceDecode(schema, data)
			if !ok {
				s.SchemaRejected++
				s.ScalarRejected++
				s.rejectHeader(providerLabel, "scalar_invalid", header)
				return 0
			}
			e.Provider = s.Providers[p].Provider
			e.ReceivedUTC = usbTraceUTC()
			e.ReceivedMS = time.Since(b.start).Milliseconds()
			e.EventUTC = usbTraceEventUTC(r.Header.Timestamp)
			if e.EventUTC == "" {
				s.TimestampUnknown++
			} else if r.Header.Timestamp < b.start.UnixNano()/100+116444736000000000 {
				s.LateEvents++
			}
			e.RunID = b.journal.Name[len("USBLink-USBMetadata-"):]
			select {
			case b.queue <- e:
			default:
				s.QueueOverflow++
			}
			return 0
		}
	}
	s.SchemaRejected++
	s.TemplateRejected++
	s.rejectHeader(providerLabel, "template_not_enabled", header)
	return 0
}

func (b *usbTraceNative) sample() {
	if b.handle == 0 {
		return
	}
	p, found, e := usbTraceQuery(b.journal)
	localUSBTrace.Lock()
	defer localUSBTrace.Unlock()
	s := &localUSBTrace.status
	if e != nil || !found {
		b.admission.Store(false)
		b.failed.Store(true)
		s.Active = false
		s.Coverage = "incomplete"
		s.Error = "USB_TRACE_QUERY_FAILED"
		return
	}
	s.EventsLost = max(s.EventsLost, p.Properties.EventsLost)
	s.RealtimeBuffersLost = max(s.RealtimeBuffersLost, p.Properties.RealTimeBuffersLost)
	if s.EventsLost > 0 || s.RealtimeBuffersLost > 0 || s.QueueOverflow > 0 || s.SchemaRejected > 0 || s.HeaderRejected > 0 || s.UnknownProvider > 0 || s.LateEvents > 0 || s.TimestampUnknown > 0 || s.ArchiveRejected > 0 {
		s.Coverage = "incomplete"
	}
}
func (b *usbTraceNative) stop() error {
	defer shutdowntrace.Begin(shutdowntrace.PhaseUSBStop)()
	if b.stopResult.done {
		return b.stopResult.err
	}
	b.stopping.Store(true)
	b.admission.Store(false)
	b.sample()
	var err error
	if b.lease != 0 {
		err = usbTraceRestoreLocked(b.dir)
	}
	if b.consumer != 0 {
		wpdCloseTrace.Call(uintptr(b.consumer))
		if b.done != nil {
			<-b.done
		}
		b.consumer = 0
	}
	if b.queue != nil {
		close(b.queue)
		<-b.workerDone
		b.queue = nil
	}
	usbTraceConsumers.Lock()
	delete(usbTraceConsumers.items, b.key)
	usbTraceConsumers.Unlock()
	if b.lease != 0 {
		windows.CloseHandle(b.lease)
		b.lease = 0
	}
	b.handle = 0
	localUSBTrace.Lock()
	localUSBTrace.status.Active = false
	localUSBTrace.status.RecoveryPending = err != nil
	if err == nil {
		localUSBTrace.status.StoppedUTC = usbTraceUTC()
		for i := range localUSBTrace.status.Providers {
			localUSBTrace.status.Providers[i].Enabled = false
		}
	} else {
		localUSBTrace.status.Phase = "recovery_pending"
		localUSBTrace.status.Error = "USB_TRACE_RECOVERY_FAILED"
		localUSBTrace.status.Coverage = "incomplete"
	}
	localUSBTrace.Unlock()
	b.stopResult.finish(err)
	return err
}
