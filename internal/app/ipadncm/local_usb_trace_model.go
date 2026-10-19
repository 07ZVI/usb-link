//go:build usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"time"
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

func newUSBTraceStatus() usbTraceStatus {
	s := usbTraceStatus{Available: true, Phase: "disabled", Coverage: "not_covered", TargetScope: "unknown", PairingVisibility: "not_available_metadata_only", SchemaScope: "installed_manifest_versions"}
	s.ReceivedMeaning = "known_usb_provider_callbacks_not_requests"
	for i, n := range []string{"USBHUB3", "UCX", "USBXHCI"} {
		s.Providers[i].Provider = n
	}
	return s
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

type usbTraceProviderStatus struct {
	Provider   string `json:"provider"`
	Enumerated int    `json:"enumerated"`
	SafeIDs    int    `json:"safe_ids"`
	Omitted    int    `json:"safe_ids_omitted"`
	Rejected   int    `json:"rejected"`
	Enabled    bool   `json:"enabled"`
	Code       string `json:"code,omitempty"`
}

type usbTraceValue struct {
	Name  string `json:"name"`
	Value uint32 `json:"value"`
}

type usbTraceRejectedHeader struct {
	Provider string `json:"provider"`
	Reason   string `json:"reason"`
	EventID  uint16 `json:"event_id"`
	Version  uint8  `json:"version"`
	Opcode   uint8  `json:"opcode"`
	Size     uint16 `json:"header_size"`
	Flags    uint16 `json:"header_flags"`
	Extended uint16 `json:"extended_count"`
	Length   uint16 `json:"data_length"`
	Count    uint64 `json:"count"`
}
