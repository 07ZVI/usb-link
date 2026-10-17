package ipadncm

import (
	"encoding/binary"
	"sync"
	"time"
	"unicode/utf16"
)

// Only names with explicitly non-content meanings are admitted. A numeric
// type alone does not make an identifier, pointer or packed payload safe.
var usbTraceNames = map[string]bool{
	"PortNumber": true, "DeviceAddress": true, "EndpointAddress": true,
	"ConfigurationValue": true, "InterfaceNumber": true, "AlternateSetting": true,
	"Status": true, "UsbdStatus": true, "NTStatus": true, "State": true,
	"PreviousState": true, "NewState": true, "Speed": true, "TransferType": true,
	"MaxPacketSize": true, "NumberOfPorts": true, "EndpointType": true,
}

type usbTraceSchema struct {
	Descriptor [16]byte
	Fields     [8]wpdManifestField
	Count      int
	Bytes      int
}

func usbTraceScalarSize(t uint16) int {
	switch t {
	case 4:
		return 1
	case 6:
		return 2
	case 8, 13, 20:
		return 4
	}
	return 0
}

func usbTraceSafeSchema(b []byte, descriptor [16]byte, guid [16]byte) (usbTraceSchema, string) {
	s := usbTraceSchema{Descriptor: descriptor}
	if len(b) < 112 {
		return s, "metadata_invalid"
	}
	var actualGUID [16]byte
	copy(actualGUID[:], b[:16])
	var actualDescriptor [16]byte
	copy(actualDescriptor[:], b[32:48])
	if actualGUID != guid || actualDescriptor != descriptor {
		return s, "identity_mismatch"
	}
	fields, n, top, stage := wpdManifestDefinition(b)
	if stage != "complete" || n != top || n > 8 {
		return s, "unsafe_layout"
	}
	for i := 0; i < int(n); i++ {
		f := fields[i]
		width := usbTraceScalarSize(f.InType)
		// Reject maps and every union flag, including fixed arrays and custom
		// schemas. Accept only the default or matching scalar output representation.
		if !usbTraceNames[f.Name] || width == 0 || !usbTraceScalarOutput(f.InType, f.OutType) || f.Flags != 0 || f.Count != 1 || f.Length != 0 && int(f.Length) != width || binary.LittleEndian.Uint32(b[112+i*24+12:]) != 0 {
			return s, "unsafe_property"
		}
		s.Fields[i] = f
		s.Bytes += width
	}
	s.Count = int(n)
	return s, ""
}

// EVENT_ID filtering cannot distinguish versions. One unsafe or unreadable
// version therefore rejects the entire ID, even if another version is safe.
func usbTraceSafeIDs(schemas []usbTraceSchema, rejected map[uint16]bool) ([]uint16, []usbTraceSchema) {
	seen := map[uint16]bool{}
	var ids []uint16
	var out []usbTraceSchema
	for _, s := range schemas {
		id := binary.LittleEndian.Uint16(s.Descriptor[:])
		if rejected[id] {
			continue
		}
		if !seen[id] {
			if len(ids) == 64 {
				continue
			}
			ids = append(ids, id)
			seen[id] = true
		}
		out = append(out, s)
	}
	return ids, out
}

type usbTraceValue struct {
	Name  string `json:"name"`
	Value uint32 `json:"value"`
}
type usbTraceEvent struct {
	RunID       string           `json:"run_id"`
	EventUTC    string           `json:"event_utc,omitempty"`
	Provider    string           `json:"provider"`
	EventID     uint16           `json:"event_id"`
	Version     uint8            `json:"version"`
	ReceivedUTC string           `json:"received_utc"`
	ReceivedMS  int64            `json:"received_ms"`
	TargetScope string           `json:"target_scope"`
	Count       int              `json:"field_count"`
	Values      [8]usbTraceValue `json:"values"`
}

func usbTraceDecode(s usbTraceSchema, payload []byte) (usbTraceEvent, bool) {
	e := usbTraceEvent{EventID: binary.LittleEndian.Uint16(s.Descriptor[:]), Version: s.Descriptor[2], TargetScope: "unknown", Count: s.Count}
	if s.Count < 0 || s.Count > len(s.Fields) || len(payload) != s.Bytes {
		return e, false
	}
	offset := 0
	for i := 0; i < s.Count; i++ {
		f := s.Fields[i]
		size := usbTraceScalarSize(f.InType)
		if size == 0 || offset+size > len(payload) {
			return e, false
		}
		var n uint32
		switch size {
		case 1:
			n = uint32(payload[offset])
		case 2:
			n = uint32(binary.LittleEndian.Uint16(payload[offset:]))
		case 4:
			n = binary.LittleEndian.Uint32(payload[offset:])
		default:
			return e, false
		}
		if f.InType == 13 && n > 1 {
			return e, false
		}
		e.Values[i] = usbTraceValue{f.Name, n}
		offset += size
	}
	return e, offset == len(payload)
}

type usbTraceProviderStatus struct {
	Provider   string `json:"provider"`
	Enumerated int    `json:"enumerated"`
	SafeIDs    int    `json:"safe_ids"`
	Omitted    int    `json:"safe_ids_omitted"`
	Rejected   int    `json:"rejected"`
	Enabled    bool   `json:"enabled"`
	Code       string `json:"code,omitempty"`
}
type usbTraceStatus struct {
	QueryOwnership        usbTraceQueryEvidence     `json:"query_ownership"`
	FirstQueryFailure     usbTraceQueryEvidence     `json:"first_query_failure"`
	RecoveryPending       bool                      `json:"recovery_pending"`
	SchemaScope           string                    `json:"schema_scope"`
	RunID                 string                    `json:"run_id,omitempty"`
	LateEvents            uint64                    `json:"late_events"`
	TimestampUnknown      uint64                    `json:"timestamp_unknown"`
	Available             bool                      `json:"available"`
	Requested             bool                      `json:"requested"`
	Active                bool                      `json:"active"`
	Phase                 string                    `json:"phase"`
	Coverage              string                    `json:"coverage"`
	TargetScope           string                    `json:"target_scope"`
	Error                 string                    `json:"error,omitempty"`
	StartedUTC            string                    `json:"started_utc,omitempty"`
	LastEventUTC          string                    `json:"last_event_utc,omitempty"`
	StoppedUTC            string                    `json:"stopped_utc,omitempty"`
	Providers             [3]usbTraceProviderStatus `json:"providers"`
	Received              uint64                    `json:"received"`
	ReceivedMeaning       string                    `json:"received_semantics"`
	CallbacksReceived     uint64                    `json:"callbacks_received"`
	SessionMetadata       uint64                    `json:"session_metadata_callbacks"`
	SessionHeaders        uint64                    `json:"session_header_callbacks"`
	UnknownProvider       uint64                    `json:"unknown_provider_callbacks"`
	HeaderRejected        uint64                    `json:"invalid_header_callbacks"`
	ShapeRejected         uint64                    `json:"known_provider_shape_rejected"`
	TemplateRejected      uint64                    `json:"known_provider_template_rejected"`
	ScalarRejected        uint64                    `json:"known_provider_scalar_rejected"`
	RejectedHeaders       [8]usbTraceRejectedHeader `json:"rejected_headers"`
	RejectedHeaderCount   int                       `json:"rejected_header_count"`
	RejectedHeaderOmitted uint64                    `json:"rejected_header_signatures_omitted"`
	Accepted              uint64                    `json:"accepted"`
	QueueOverflow         uint64                    `json:"queue_overflow"`
	SchemaRejected        uint64                    `json:"schema_rejected"`
	EventsLost            uint32                    `json:"events_lost"`
	RealtimeBuffersLost   uint32                    `json:"realtime_buffers_lost"`
	ArchiveRejected       uint64                    `json:"archive_rejected"`
	Recent                [4]usbTraceEvent          `json:"recent"`
	RecentCount           int                       `json:"recent_count"`
	RecentOmitted         uint64                    `json:"recent_omitted"`
	PairingVisibility     string                    `json:"pairing_visibility"`
}

func newUSBTraceStatus() usbTraceStatus {
	s := usbTraceStatus{Available: true, Phase: "disabled", Coverage: "not_covered", TargetScope: "unknown", PairingVisibility: "not_available_metadata_only", SchemaScope: "installed_manifest_versions"}
	s.ReceivedMeaning = "known_usb_provider_callbacks_not_requests"
	for i, n := range []string{"USBHUB3", "UCX", "USBXHCI"} {
		s.Providers[i].Provider = n
	}
	return s
}
func usbTraceUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func usbTraceOmittedIDs(schemas []usbTraceSchema, rejected map[uint16]bool, retained int) int {
	seen := map[uint16]bool{}
	for _, s := range schemas {
		id := binary.LittleEndian.Uint16(s.Descriptor[:])
		if !rejected[id] {
			seen[id] = true
		}
	}
	return max(0, len(seen)-retained)
}
func usbTraceEventUTC(ticks int64) string {
	if ticks < 116444736000000000 || ticks >= 200000000000000000 {
		return ""
	}
	return time.Unix(0, (ticks-116444736000000000)*100).UTC().Format(time.RFC3339Nano)
}

func usbTraceCanAdmit(requested, contextAlive, terminated, stopping bool) bool {
	return requested && contextAlive && !terminated && !stopping
}

func usbTraceScalarOutput(in, out uint16) bool {
	if usbTraceScalarSize(in) == 0 {
		return false
	}
	if out == 0 {
		return true
	}
	if in == 20 {
		return out == 18
	} // TDH input/output enum values differ for HexInt32.
	return out == in
}

func usbTraceKeywordMaskSafe(mask, forbidden uint64) bool {
	// MatchAnyKeyword zero means all keywords, not an empty selection.
	return mask != 0 && forbidden != 0 && mask&forbidden == 0
}

// Query evidence contains only comparisons and native scalar properties.
// Neither arbitrary native strings nor the protected session identity escape.
type usbTraceQueryEvidence struct {
	Observed    bool   `json:"observed"`
	NativeCode  uint32 `json:"native_code"`
	GUIDMatches bool   `json:"guid_matches"`
	NameMatches bool   `json:"name_matches"`
	NameValid   bool   `json:"name_valid"`
	FileValid   bool   `json:"file_valid"`
	FileEmpty   bool   `json:"file_empty"`
	Mode        uint32 `json:"mode"`
	MaxFile     uint32 `json:"max_file"`
	NameOffset  uint32 `json:"name_offset"`
	FileOffset  uint32 `json:"file_offset"`
	BufferBytes uint32 `json:"buffer_bytes"`
	Mismatch    uint32 `json:"mismatch"`
}

var usbTraceQueries struct {
	sync.Mutex
	last, first usbTraceQueryEvidence
}

func usbTraceRecordQuery(q usbTraceQueryEvidence) {
	usbTraceQueries.Lock()
	defer usbTraceQueries.Unlock()
	usbTraceQueries.last = q
	if q.Mismatch != 0 && !usbTraceQueries.first.Observed {
		usbTraceQueries.first = q
	}
}
func usbTraceQuerySnapshot() (usbTraceQueryEvidence, usbTraceQueryEvidence) {
	usbTraceQueries.Lock()
	defer usbTraceQueries.Unlock()
	return usbTraceQueries.last, usbTraceQueries.first
}
func usbTraceResetQueries() {
	usbTraceQueries.Lock()
	usbTraceQueries.last = usbTraceQueryEvidence{}
	usbTraceQueries.first = usbTraceQueryEvidence{}
	usbTraceQueries.Unlock()
}
func usbTraceQueryText(raw []byte, offset uint32) (string, bool) {
	if offset < 120 || offset%2 != 0 || uint64(offset)+2 > uint64(len(raw)) {
		return "", false
	}
	var value []uint16
	for i := int(offset); i+1 < len(raw) && len(value) < 1024; i += 2 {
		v := binary.LittleEndian.Uint16(raw[i:])
		if v == 0 {
			return string(utf16.Decode(value)), true
		}
		value = append(value, v)
	}
	return "", false
}
func usbTraceCompareQuery(raw []byte, q usbTraceQueryEvidence, expectedName string) usbTraceQueryEvidence {
	q.Observed = true
	if q.BufferBytes < 120 || uint64(q.BufferBytes) > uint64(len(raw)) {
		q.Mismatch |= 32
		return q
	}
	raw = raw[:q.BufferBytes]
	name, valid := usbTraceQueryText(raw, q.NameOffset)
	q.NameValid = valid
	q.NameMatches = valid && name == expectedName
	q.FileEmpty = q.FileOffset == 0
	q.FileValid = q.FileEmpty
	if q.FileOffset != 0 {
		file, valid := usbTraceQueryText(raw, q.FileOffset)
		q.FileValid = valid
		q.FileEmpty = valid && file == ""
	}
	if !q.GUIDMatches {
		q.Mismatch |= 1
	}
	if !q.NameMatches {
		q.Mismatch |= 2
	}
	if !usbTraceSessionModeOwned(q.Mode) {
		q.Mismatch |= 4
	}
	if q.MaxFile != 0 {
		q.Mismatch |= 8
	}
	if !q.FileValid || !q.FileEmpty {
		q.Mismatch |= 16
	}
	return q
}

// The controller may call stop again from its deferred cleanup. An already
// failed cleanup must never become success just because its handle was closed.
type usbTraceStopResult struct {
	done bool
	err  error
}

func (r *usbTraceStopResult) finish(err error) {
	if !r.done {
		r.done = true
		r.err = err
	}
}

const usbTraceRealtimeMode uint32 = 0x00000100
const usbTraceStopOnHybridShutdown uint32 = 0x00400000
const usbTracePersistOnHybridShutdown uint32 = 0x00800000

// Windows may add exactly one documented hybrid-shutdown policy when an
// older receipt's session was created without an explicit policy.
func usbTraceSessionModeOwned(mode uint32) bool {
	switch mode {
	case usbTraceRealtimeMode, usbTraceRealtimeMode | usbTraceStopOnHybridShutdown, usbTraceRealtimeMode | usbTracePersistOnHybridShutdown:
		return true
	default:
		return false
	}
}
