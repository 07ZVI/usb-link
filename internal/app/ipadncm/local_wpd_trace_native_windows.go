//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"sync"
	"time"
	"unsafe"
)

var wpdStartTrace = windows.NewLazySystemDLL("advapi32.dll").NewProc("StartTraceW")
var wpdEnableTrace = windows.NewLazySystemDLL("advapi32.dll").NewProc("EnableTraceEx2")
var wpdEnumerateProviders = windows.NewLazySystemDLL("tdh.dll").NewProc("TdhEnumerateProviders")
var wpdEnumerateTraceGUIDs = windows.NewLazySystemDLL("advapi32.dll").NewProc("EnumerateTraceGuidsEx")
var wpdProviderLabels = [3]string{"api", "mtp", "usb"}

type localWPDTraceNative struct {
	dir               string
	lease             windows.Handle
	journal           localWPDTraceJournal
	consumer          uint64
	consumerDone      chan struct{}
	consumerKey       uintptr
	traceHandle       uint64
	allowed           func() bool
	nextProviderCheck time.Time
	providers         [3]windows.GUID
	providerSchemas   [3]string
	safeEventIDs      [3][]uint16
	projections       []wpdProjectionDefinition
	mu                sync.Mutex
	data              localWPDTraceSample
	sampling          wpdTraceSamplingGate
	consumerError     uint32
	stamp             func() int64
	critical          *wpdCriticalQueue
	criticalDone      chan struct{}
	summaryQueue      *wpdCriticalQueue
	summaryDone       chan struct{}
	nextArchiveSample time.Time
}

func (b *localWPDTraceNative) recover() error {
	if b.lease != 0 {
		return b.stop()
	}
	return RestoreLocalWPDTrace(b.dir)
}
func discoverWPDProviders() ([3]wpdTraceCatalogEntry, error) {
	var out [3]wpdTraceCatalogEntry
	var size uint32
	r, _, _ := wpdEnumerateProviders.Call(0, uintptr(unsafe.Pointer(&size)))
	if r != 122 || size < 8 || size > 4<<20 {
		return out, wpdTraceError("WPD_TRACE_PROVIDER_QUERY_FAILED", uint32(r))
	}
	buf := make([]byte, size)
	r, _, _ = wpdEnumerateProviders.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return out, wpdTraceError("WPD_TRACE_PROVIDER_QUERY_FAILED", uint32(r))
	}
	if size < 8 || uint64(size) > uint64(len(buf)) {
		return out, wpdTraceError("WPD_TRACE_PROVIDER_METADATA_INVALID", 0)
	}
	return wpdTraceProviderCatalog(buf[:size])
}

func (b *localWPDTraceNative) start(allowed func() bool) error {
	if !allowed() {
		return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
	}
	b.mu.Lock()
	b.data = newWPDTraceProviderSample()
	b.sampling = wpdTraceSamplingGate{}
	b.consumerError = 0
	b.nextArchiveSample = time.Time{}
	b.mu.Unlock()
	catalog, e := discoverWPDProviders()
	if e != nil {
		b.mu.Lock()
		for i := range b.data.Providers {
			b.data.Providers[i].SkipCode = "discovery_failed"
			var failure *localWPDTraceFailure
			if errors.As(e, &failure) {
				b.data.Providers[i].NativeCode = failure.Native
			}
		}
		b.mu.Unlock()
		return e
	}
	// Once per explicit start; outside the callback, sampling gate and state lock.
	templates := readWPDManifestTemplates(catalog, allowed)
	b.mu.Lock()
	b.data.ManifestTemplates = templates
	b.mu.Unlock()
	if !allowed() {
		return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
	}
	lease, e := openLocalWPDTraceLease(b.dir)
	if e != nil {
		return e
	}
	b.lease = lease
	if e = restoreLocalWPDTraceLocked(b.dir, b.lease); e != nil {
		return e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return wpdTraceError("WPD_TRACE_RANDOM_FAILED", 0)
	}
	guid, e := windows.GenerateGUID()
	if e != nil {
		return wpdTraceError("WPD_TRACE_RANDOM_FAILED", wpdNativeCode(e))
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return wpdTraceError("WPD_TRACE_OWNER_UNPROVEN", wpdNativeCode(e))
	}
	j := localWPDTraceJournal{Schema: 2, Mode: "metadata_session", Session: "USBLink-WPD-" + hex.EncodeToString(nonce[:]), GUID: guid.String(), OwnerSID: user.User.Sid.String(), File: ""}
	if !allowed() {
		return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
	}
	if e = writeLocalWPDTraceJournal(b.dir, j); e != nil {
		return e
	}
	b.journal = j
	path := ""
	props, e := wpdMetadataProperties(j)
	if e != nil {
		return e
	}
	if !allowed() {
		return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
	}
	var handle uint64
	name, _ := windows.UTF16PtrFromString(j.Session)
	r, _, _ := wpdStartTrace.Call(uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(props)))
	if r != 0 {
		return wpdTraceError("WPD_TRACE_START_FAILED", uint32(r))
	}
	if _, found, e := queryLocalWPDTrace(j, path); e != nil {
		return e
	} else if !found {
		return wpdTraceError("WPD_TRACE_START_UNCONFIRMED", 0)
	}
	b.mu.Lock()
	var providers [3]windows.GUID
	for i, p := range catalog {
		providers[i] = *(*windows.GUID)(unsafe.Pointer(&p.GUID[0]))
		b.providerSchemas[i] = p.Schema
	}
	b.providers = providers
	b.mu.Unlock()
	b.projections = readWPDProjectionDefinitions(catalog[1], "mtp", allowed)
	b.safeEventIDs = [3][]uint16{}
	for _, d := range b.projections {
		b.safeEventIDs[1] = append(b.safeEventIDs[1], binary.LittleEndian.Uint16(d.Descriptor[:]))
	}
	b.traceHandle, b.allowed = handle, allowed
	if e = b.openConsumer(); e != nil {
		return e
	}
	return b.refreshProviders()
}

// Only append providers to our existing session. Successful providers are not
// re-enabled, and no foreign logger is stopped or reconfigured.
func (b *localWPDTraceNative) refreshProviders() error {
	b.nextProviderCheck = time.Now().Add(5 * time.Second)
	if b.allowed == nil || !b.allowed() {
		return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
	}
	b.mu.Lock()
	providers, statuses, schemas := b.providers, b.data.Providers, b.providerSchemas
	b.mu.Unlock()
	missing := false
	for _, p := range providers {
		missing = missing || p == (windows.GUID{})
	}
	if missing {
		discovered, e := discoverWPDProviders()
		if e != nil {
			return e
		}
		for i := range providers {
			if providers[i] == (windows.GUID{}) {
				providers[i] = *(*windows.GUID)(unsafe.Pointer(&discovered[i].GUID[0]))
				schemas[i] = discovered[i].Schema
			}
		}
		b.mu.Lock()
		b.providers = providers
		b.providerSchemas = schemas
		b.mu.Unlock()
	}
	e := enableLocalWPDTraceProviders(b.allowed, func(i int) localWPDTraceProvider {
		if statuses[i].Enabled {
			return statuses[i]
		}
		p := wpdProviderUnused(providers[i])
		p.Schema = schemas[i]
		if len(b.safeEventIDs[i]) == 0 {
			switch i {
			case 0:
				p.SkipCode = "no_reviewed_target"
			case 2:
				p.SkipCode = "projection_not_supported"
			default:
				p.SkipCode = "projection_template_unproven"
			}
		} else if p.Kind != "modern" || p.Schema != "manifest" {
			p.SkipCode = "native_filter_unproven"
		}
		return p
	}, func(i int) uint32 {
		return enableWPDMetadataEvents(b.traceHandle, providers[i], b.safeEventIDs[i])
	}, b.recordProvider)
	runtime.KeepAlive(providers)
	return e
}

func (b *localWPDTraceNative) recordProvider(i int, p localWPDTraceProvider) {
	if p.Enabled && p.EnabledUTC == "" {
		p.EnabledUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b.mu.Lock()
	b.data.Providers[i] = p
	b.data.providerCoverage()
	b.mu.Unlock()
}
func (b *localWPDTraceNative) cachedSample() localWPDTraceSample {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.data
	if b.critical != nil {
		s.CriticalArchive = b.critical.snapshot()
	}
	if b.summaryQueue != nil {
		s.SummaryArchive = b.summaryQueue.snapshot()
	}
	s.Recent = append([]localWPDTraceEvent(nil), s.Recent...)
	return s
}
func (b *localWPDTraceNative) stop() error {
	defer shutdowntrace.Begin(shutdowntrace.PhaseWPDStop)()
	if b.lease == 0 {
		return b.recover()
	}
	e := restoreLocalWPDTraceLocked(b.dir, b.lease)
	// Close our consumer even if ownership verification prevents stopping ETW.
	// The protected journal remains for a later explicit recovery attempt.
	b.closeConsumer()
	windows.CloseHandle(b.lease)
	b.lease = 0
	return e
}
func (b *localWPDTraceNative) sample() (sample localWPDTraceSample, err error) {
	defer func() {
		if !time.Now().Before(b.nextArchiveSample) {
			b.nextArchiveSample = time.Now().Add(5 * time.Second)
			type archiveSample localWPDTraceSample
			RecordConnectionArchiveEvent("wpd_snapshot", archiveSample(sample))
		}
	}()
	b.mu.Lock()
	s := b.data
	if b.critical != nil {
		s.CriticalArchive = b.critical.snapshot()
	}
	if b.summaryQueue != nil {
		s.SummaryArchive = b.summaryQueue.snapshot()
	}
	s.Recent = append([]localWPDTraceEvent(nil), s.Recent...)
	ce := b.consumerError
	b.mu.Unlock()
	if ce != 0 {
		return s, wpdTraceError("WPD_TRACE_CONSUMER_FAILED", ce)
	}
	if b.consumerDone != nil {
		select {
		case <-b.consumerDone:
			return s, wpdTraceError("WPD_TRACE_CONSUMER_ENDED", 0)
		default:
		}
	}
	props, found, e := queryLocalWPDTrace(b.journal, "")
	if e != nil {
		return s, e
	}
	if !found {
		return s, wpdTraceError("WPD_TRACE_SESSION_ENDED", 0)
	}
	if !time.Now().Before(b.nextProviderCheck) {
		if e = b.refreshProviders(); e != nil {
			return b.cachedSample(), e
		}
		s = b.cachedSample()
	}
	s.EventsLost = b.retainEventsLost(props.Properties.EventsLost)
	return s, nil
}

// Preserve already observed loss when final stop can only expose cached state.
func (b *localWPDTraceNative) retainEventsLost(observed uint32) uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data.EventsLost = max(b.data.EventsLost, observed)
	return b.data.EventsLost
}
func (b *localWPDTraceNative) record(r *wpdEventRecord) {
	// This start-specific predicate reads only controller memory. OFF, an obsolete
	// revision or cancellation denies new captures before any payload copy. A
	// callback admitted before revocation may finish copying its bounded record.
	if b.allowed == nil || !b.allowed() {
		b.mu.Lock()
		b.data.CaptureDenied++
		b.mu.Unlock()
		return
	}
	b.mu.Lock()
	providers := b.providers
	b.mu.Unlock()
	ms := int64(-1)
	if b.stamp != nil {
		ms = b.stamp()
	}
	attempt := currentSoftwareAttempt()
	// The loss-sensitive queue is admitted first and has its own capacity.
	projected := b.projectRecord(r, providers[1], ms, attempt)
	b.captureCriticalProjection(r, projected)
	label := ""
	for i, p := range providers {
		if p == r.Header.Provider {
			label = wpdProviderLabels[i]
			break
		}
	}
	now := time.Now()
	b.mu.Lock()
	if label != "" {
		b.data.Events++
	} else {
		b.data.Unmapped++
	}
	header := localWPDTraceSchema{Provider: label, EventID: r.Header.Descriptor.ID, Version: r.Header.Descriptor.Version, HeaderFlags: r.Header.Flags, DataLength: r.UserDataLength}
	admitted := b.sampling.admit(now.Unix(), &b.data, header)
	b.mu.Unlock()
	if !admitted {
		RecordConnectionArchiveEvent("wpd_skipped_header", struct {
			Attempt uint64              `json:"software_attempt"`
			Header  localWPDTraceSchema `json:"header"`
			Event   localWPDTraceEvent  `json:"event"`
		}{attempt, header, wpdEventSummary(r.Header, label, ms)})
		return
	}
	b.captureSummaryProjection(r, projected)
}

// Only worker-owned event copies reach this decoder. The callback has already
// applied the unchanged realtime sampling budget and counted the header.
func (b *localWPDTraceNative) decodeSummary(r *wpdEventRecord, providers [3]windows.GUID, ms int64, attempt uint64) (bool, bool, bool) {
	label := ""
	for i, p := range providers {
		if p == r.Header.Provider {
			label = wpdProviderLabels[i]
			break
		}
	}
	metadata, metadataStage, metadataCode := wpdEventMetadata(r)
	if label == "" && len(metadata) >= 16 {
		provider := *(*windows.GUID)(unsafe.Pointer(&metadata[0]))
		for i, p := range providers {
			if provider == p {
				label = wpdProviderLabels[i]
				break
			}
		}
		if label != "" {
			b.mu.Lock()
			b.data.Events++
			b.data.Unmapped--
			b.mu.Unlock()
		}
	}
	if label == "" {
		archived := RecordConnectionArchiveEventAccepted("wpd_event", struct {
			Attempt uint64             `json:"software_attempt"`
			Event   localWPDTraceEvent `json:"event"`
			Stage   string             `json:"stage"`
		}{attempt, wpdEventSummary(r.Header, "unknown", ms), "provider_unmapped"})
		return false, false, archived
	}
	event := wpdEventSummary(r.Header, label, ms)
	// Strict decoding cannot acquire a provider identity through the legacy
	// metadata fallback. Both native identities must match our installed catalog.
	trustedMTP := providers[1] != (windows.GUID{}) && r.Header.Provider == providers[1] && len(metadata) >= 16 && *(*windows.GUID)(unsafe.Pointer(&metadata[0])) == providers[1]
	field, value, schema, response := wpdDecodeCommand(r, metadata, metadataStage, metadataCode, trustedMTP)
	event.CommandField, event.CommandCode, event.OpcodeDecoded = field, value, schema.Stage == "decoded"
	event.Response = response
	schema.Provider = label
	b.mu.Lock()
	if event.OpcodeDecoded {
		event.CommandRole = wpdDecodedCommandRole(event)
		b.data.Decoded++
		b.data.retainDecoded(event)
	}
	b.data.recordDecode(schema)
	b.data.Recent = append(b.data.Recent, event)
	if len(b.data.Recent) > 8 {
		b.data.Recent = append([]localWPDTraceEvent(nil), b.data.Recent[len(b.data.Recent)-8:]...)
	}
	b.mu.Unlock()
	archived := RecordConnectionArchiveEventAccepted("wpd_event", struct {
		Attempt uint64              `json:"software_attempt"`
		Event   localWPDTraceEvent  `json:"event"`
		Schema  localWPDTraceSchema `json:"schema"`
	}{attempt, event, schema})
	responseFailed := event.OpcodeDecoded && event.EventID == 2001 && event.Response != (wpdMTPResponse{}) && (!event.Response.CodeRead || !event.Response.TransportRead)
	return event.OpcodeDecoded, responseFailed, archived
}

func wpdProviderUnused(provider windows.GUID) localWPDTraceProvider {
	out := localWPDTraceProvider{Kind: "unknown", SkipCode: "query_failed", Registration: "query_failed"}
	if provider == (windows.GUID{}) {
		out.SkipCode = "unavailable"
		out.Registration = "not_installed"
		return out
	}
	var size uint32
	r, _, _ := wpdEnumerateTraceGUIDs.Call(1, uintptr(unsafe.Pointer(&provider)), 16, 0, 0, uintptr(unsafe.Pointer(&size)))
	if r == 4200 {
		out.SkipCode = "type_unknown"
		out.Registration = "not_registered"
		out.NativeCode = 4200
		return out
	}
	if r != 122 || size < 8 || size > 65536 {
		out.NativeCode = uint32(r)
		return out
	}
	b := make([]byte, size)
	r, _, _ = wpdEnumerateTraceGUIDs.Call(1, uintptr(unsafe.Pointer(&provider)), 16, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&size)))
	if r == 4200 {
		out.SkipCode = "type_unknown"
		out.Registration = "not_registered"
		out.NativeCode = 4200
		return out
	}
	if r != 0 {
		out.NativeCode = uint32(r)
		return out
	}
	if size < 8 || uint64(size) > uint64(len(b)) {
		out.SkipCode = "metadata_invalid"
		out.Registration = "metadata_invalid"
		return out
	}
	return wpdTraceProviderUnusedMetadata(b[:size])
}
