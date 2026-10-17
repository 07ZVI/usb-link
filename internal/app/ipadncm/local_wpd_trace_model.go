package ipadncm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf16"
)

const localWPDTraceJournalFile = "local-wpd-trace-v1.json"
const localWPDTraceETLFile = "local-wpd-trace.etl"
const localWPDTraceJournalLimit = 4096

var wpdProviders = [3]string{"Microsoft-Windows-WPD-API", "Microsoft-Windows-WPD-MTPClassDriver", "Microsoft-Windows-WPD-MTPUS"}

type localWPDTraceJournal struct {
	Schema   int    `json:"schema"`
	Session  string `json:"session"`
	GUID     string `json:"guid"`
	OwnerSID string `json:"owner_sid"`
	File     string `json:"file"`
	Mode     string `json:"mode,omitempty"`
	Stopped  bool   `json:"stopped"`
}

func (j localWPDTraceJournal) valid() bool {
	nonce := strings.TrimPrefix(j.Session, "USBLink-WPD-")
	format := j.Schema == 1 && j.Mode == "" && j.File == localWPDTraceETLFile || j.Schema == 2 && j.Mode == "metadata_session" && j.File == ""
	return format && len(nonce) == 32 && strings.Trim(nonce, "0123456789abcdef") == "" && j.Session == "USBLink-WPD-"+nonce &&
		len(j.GUID) == 38 && j.GUID[0] == '{' && j.GUID[37] == '}' && j.GUID[9] == '-' && j.GUID[14] == '-' && j.GUID[19] == '-' && j.GUID[24] == '-' && strings.Trim(j.GUID, "{}-0123456789abcdefABCDEF") == "" &&
		strings.HasPrefix(j.OwnerSID, "S-1-") && len(j.OwnerSID) <= 184 && strings.Trim(j.OwnerSID[4:], "0123456789-") == ""
}
func decodeLocalWPDTraceJournal(b []byte) (localWPDTraceJournal, error) {
	var j localWPDTraceJournal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > localWPDTraceJournalLimit || d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
		return j, errors.New("WPD_TRACE_JOURNAL_INVALID")
	}
	return j, nil
}

type localWPDTraceFailure struct {
	Code      string
	Native    uint32
	Ownership *wpdSessionQueryEvidence
}

func (e *localWPDTraceFailure) Error() string { return e.Code }
func wpdTraceError(code string, native uint32) error {
	return &localWPDTraceFailure{Code: code, Native: native}
}

type localWPDTraceEvent struct {
	Provider        string         `json:"provider"`
	EventID         uint16         `json:"event_id"`
	Version         uint8          `json:"version"`
	PID             uint32         `json:"pid"`
	Task            uint16         `json:"task"`
	ETWOpcode       uint8          `json:"etw_opcode"`
	MS              int64          `json:"received_ms"`
	EventUTC        string         `json:"event_utc,omitempty"`
	OpcodeDecoded   bool           `json:"opcode_decoded"`
	CommandField    string         `json:"command_field,omitempty"`
	CommandCode     uint64         `json:"command_code,omitempty"`
	CommandRole     string         `json:"command_role,omitempty"`
	Response        wpdMTPResponse `json:"response,omitzero"`
	Observations    uint64         `json:"observations,omitempty"`
	ObservationUnit string         `json:"observation_unit,omitempty"`
	LastReceivedMS  int64          `json:"last_received_ms"`
	LastEventUTC    string         `json:"last_event_utc,omitempty"`
	LastResponse    wpdMTPResponse `json:"last_response,omitzero"`
}

type wpdMTPResponse struct {
	CodeRead        bool   `json:"code_read"`
	Code            uint16 `json:"code"`
	CodeError       string `json:"code_error,omitempty"`
	CodeNative      uint32 `json:"code_native,omitempty"`
	TransportRead   bool   `json:"transport_read"`
	TransportHR     uint32 `json:"transport_hr"`
	TransportError  string `json:"transport_error,omitempty"`
	TransportNative uint32 `json:"transport_native,omitempty"`
}
type wpdFirstDecoded [8]localWPDTraceEvent

func (s wpdFirstDecoded) MarshalJSON() ([]byte, error) {
	n := 0
	for n < len(s) && s[n].Provider != "" {
		n++
	}
	return json.Marshal(s[:n])
}
func (s *localWPDTraceSample) retainDecoded(e localWPDTraceEvent) {
	if !e.OpcodeDecoded {
		return
	}
	for i, old := range s.FirstDecoded {
		if old.Provider == e.Provider && old.EventID == e.EventID && old.Version == e.Version && old.CommandCode == e.CommandCode {
			// These count observed ETW events, never sends, pairings or prompts.
			if s.FirstDecoded[i].Observations < ^uint64(0) {
				s.FirstDecoded[i].Observations++
			}
			s.FirstDecoded[i].LastReceivedMS = e.MS
			s.FirstDecoded[i].LastEventUTC = e.EventUTC
			s.FirstDecoded[i].LastResponse = e.Response
			return
		}
		if old.Provider == "" {
			e.Observations = 1
			e.ObservationUnit = "etw_events"
			e.LastReceivedMS = e.MS
			e.LastEventUTC = e.EventUTC
			e.LastResponse = e.Response
			s.FirstDecoded[i] = e
			return
		}
	}
	s.DecodedUnretainedEvents++
}

type localWPDTraceSample struct {
	CaptureMode             string                    `json:"capture_mode,omitempty"`
	CaptureDenied           uint64                    `json:"capture_denied,omitempty"`
	Events                  uint64                    `json:"events"`
	Decoded                 uint64                    `json:"decoded"`
	SampledOut              uint64                    `json:"sampled_out"`
	Unmapped                uint64                    `json:"unmapped_events"`
	EventsLost              uint32                    `json:"events_lost"`
	Recent                  []localWPDTraceEvent      `json:"recent,omitempty"`
	DecodeCounts            localWPDTraceDecodeCounts `json:"decode_counts"`
	Schemas                 localWPDTraceSchemas      `json:"schemas"`
	SchemasOmitted          uint8                     `json:"schemas_omitted,omitempty"`
	RecentOmitted           uint8                     `json:"recent_omitted,omitempty"`
	SchemaUnretainedEvents  uint64                    `json:"schema_unretained_events,omitempty"`
	HeaderOnlyEvents        uint64                    `json:"header_only_events,omitempty"`
	CriticalSampling        wpdCriticalSampling       `json:"critical_sampling,omitzero"`
	CriticalArchive         wpdCriticalArchiveCounts  `json:"critical_archive,omitzero"`
	SummaryArchive          wpdCriticalArchiveCounts  `json:"summary_archive,omitzero"`
	ManifestTemplates       wpdManifestTemplates      `json:"manifest_templates"`
	ManifestOmitted         uint8                     `json:"manifest_omitted,omitempty"`
	FirstDecoded            wpdFirstDecoded           `json:"first_decoded"`
	DecodedUnretainedEvents uint64                    `json:"decoded_unretained_events,omitempty"`
	DecodedOmitted          uint8                     `json:"decoded_omitted,omitempty"`
	ProviderDetailsOmitted  uint8                     `json:"provider_details_omitted,omitempty"`
	ProviderCoverage        string                    `json:"provider_coverage"`
	EnabledProviderCount    int                       `json:"enabled_provider_count"`
	Providers               [3]localWPDTraceProvider  `json:"providers"`
}

type localWPDTraceProvider struct {
	Label               string `json:"label"`
	Kind                string `json:"kind"`
	OtherLoggerCount    uint32 `json:"other_logger_count"`
	Enabled             bool   `json:"enabled"`
	EnabledUTC          string `json:"enabled_utc,omitempty"`
	SkipCode            string `json:"skip_code,omitempty"`
	NativeCode          uint32 `json:"native_code,omitempty"`
	Registration        string `json:"registration,omitempty"`
	InstanceCount       uint32 `json:"instance_count,omitempty"`
	FlagsOR             uint32 `json:"flags_or,omitempty"`
	Schema              string `json:"schema,omitempty"`
	ModernInstances     uint32 `json:"modern_instances,omitempty"`
	LegacyInstances     uint32 `json:"legacy_instances,omitempty"`
	PreEnabledInstances uint32 `json:"pre_enabled_instances,omitempty"`
	UnknownInstances    uint32 `json:"unknown_instances,omitempty"`
}

type wpdTraceCatalogEntry struct {
	GUID   [16]byte
	Schema string
	Found  bool
}

// TDH names describe installed metadata, not a live registration. The schema
// is diagnostic only and must never substitute for the runtime Flags check.
func wpdTraceProviderCatalog(b []byte) ([3]wpdTraceCatalogEntry, error) {
	var out [3]wpdTraceCatalogEntry
	if len(b) < 8 || len(b) > 4<<20 {
		return out, wpdTraceError("WPD_TRACE_PROVIDER_METADATA_INVALID", 0)
	}
	count := binary.LittleEndian.Uint32(b)
	end := uint64(count)*24 + 8
	if end > uint64(len(b)) {
		return out, wpdTraceError("WPD_TRACE_PROVIDER_METADATA_INVALID", 0)
	}
	for i := uint32(0); i < count; i++ {
		v := b[8+uint64(i)*24:]
		offset := binary.LittleEndian.Uint32(v[20:])
		if uint64(offset) < end {
			return out, wpdTraceError("WPD_TRACE_PROVIDER_METADATA_INVALID", 0)
		}
		name := wpdTraceUTF16(b, offset, 128)
		for p, want := range wpdProviders {
			if name != want {
				continue
			}
			if out[p].Found {
				return out, wpdTraceError("WPD_TRACE_PROVIDER_AMBIGUOUS", 0)
			}
			copy(out[p].GUID[:], v[:16])
			if out[p].GUID == ([16]byte{}) {
				return out, wpdTraceError("WPD_TRACE_PROVIDER_METADATA_INVALID", 0)
			}
			out[p].Found = true
			out[p].Schema = "unknown"
			switch binary.LittleEndian.Uint32(v[16:]) {
			case 0:
				out[p].Schema = "manifest"
			case 1:
				out[p].Schema = "mof"
			}
		}
	}
	return out, nil
}

func newWPDTraceProviderSample() localWPDTraceSample {
	s := localWPDTraceSample{ProviderCoverage: "none", CaptureMode: "scalar_projection"}
	for i, label := range [3]string{"api", "mtp", "usb"} {
		s.Providers[i] = localWPDTraceProvider{Label: label, Kind: "unknown", SkipCode: "not_checked"}
	}
	return s
}

func (s *localWPDTraceSample) providerCoverage() {
	s.EnabledProviderCount = 0
	for _, p := range s.Providers {
		if p.Enabled {
			s.EnabledProviderCount++
		}
	}
	s.ProviderCoverage = "none"
	if s.EnabledProviderCount == 3 {
		s.ProviderCoverage = "complete"
	} else if s.EnabledProviderCount > 0 {
		s.ProviderCoverage = "partial"
	}
}

func enableLocalWPDTraceProviders(allowed func() bool, inspect func(int) localWPDTraceProvider, enable func(int) uint32, record func(int, localWPDTraceProvider)) error {
	enabled := 0
	privacyBlocked := false
	waiting, failed := false, false
	for i, label := range [3]string{"api", "mtp", "usb"} {
		if !allowed() {
			return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
		}
		p := inspect(i)
		p.Label = label
		if p.Enabled {
			enabled++
			record(i, p)
			continue
		}
		if p.Kind != "modern" && p.Kind != "legacy" && p.Kind != "mixed" && p.SkipCode == "" {
			p.SkipCode = "type_unknown"
		}
		if p.SkipCode == "" {
			if !allowed() {
				return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
			}
			if code := enable(i); code != 0 {
				p.SkipCode = "enable_failed"
				p.NativeCode = code
			} else {
				p.Enabled = true
				enabled++
			}
		}
		switch p.SkipCode {
		case "whole_event_not_safe", "native_filter_unproven", "no_reviewed_target", "projection_not_supported", "projection_template_unproven":
			privacyBlocked = true
		case "type_unknown", "unavailable":
			waiting = true
		case "query_failed", "metadata_invalid", "enable_failed", "discovery_failed":
			failed = true
		}
		record(i, p)
	}
	if !allowed() {
		return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
	}
	if enabled == 0 && privacyBlocked && !failed {
		return wpdTraceError("WPD_TRACE_SAFE_METADATA_NOT_COVERED", 0)
	}
	if enabled == 0 && (!waiting || failed) {
		return wpdTraceError("WPD_TRACE_NO_PROVIDER_ENABLED", 0)
	}
	return nil
}

type localWPDTraceStatus struct {
	Available     bool                     `json:"available"`
	Requested     bool                     `json:"requested"`
	Effective     bool                     `json:"effective"`
	Busy          bool                     `json:"busy"`
	Persistence   string                   `json:"persistence"`
	SavedEnabled  bool                     `json:"saved_enabled"`
	RequestID     string                   `json:"request_id,omitempty"`
	RejectedID    string                   `json:"rejected_id,omitempty"`
	RejectedError string                   `json:"rejected_error,omitempty"`
	Phase         string                   `json:"phase"`
	Error         string                   `json:"error,omitempty"`
	CauseCode     string                   `json:"cause_code,omitempty"`
	NativeCode    uint32                   `json:"native_code,omitempty"`
	Ownership     *wpdSessionQueryEvidence `json:"query_ownership,omitempty"`
	Scope         string                   `json:"scope"`
	TraceLimitMiB int                      `json:"trace_limit_mib"`
	SampledUTC    string                   `json:"sampled_utc,omitempty"`
	RunID         string                   `json:"run_id,omitempty"`
	SampledMS     int64                    `json:"sampled_ms"`
	localWPDTraceSample
}

// Keep the existing 4 KiB section contract as diagnostics gain detail. Drop
// recent samples first, then the newest schema summaries. Omission is explicit;
// the first distinct schemas remain in memory and cannot be replaced by repeats.
// Whole static templates go next; earliest decoded command evidence goes last.
func (s localWPDTraceStatus) MarshalJSON() ([]byte, error) {
	type plain localWPDTraceStatus
	for {
		b, e := json.Marshal(plain(s))
		if e != nil || len(b) <= 4096 {
			return b, e
		}
		if len(s.Recent) > 0 {
			s.Recent = s.Recent[1:]
			s.RecentOmitted++
			continue
		}
		n := len(s.Schemas) - 1
		for n >= 0 && s.Schemas[n].Provider == "" {
			n--
		}
		if n >= 0 {
			s.Schemas[n] = localWPDTraceSchema{}
			s.SchemasOmitted++
			continue
		}
		n = len(s.ManifestTemplates) - 1
		for n >= 0 && s.ManifestTemplates[n].Provider == "" {
			n--
		}
		if n >= 0 {
			s.ManifestTemplates[n] = wpdManifestTemplate{}
			s.ManifestOmitted++
			continue
		}
		n = len(s.FirstDecoded) - 1
		for n >= 0 && s.FirstDecoded[n].Provider == "" {
			n--
		}
		if n <= 0 && s.ProviderDetailsOmitted == 0 {
			// Preserve the earliest decoded event and delivery counters even at their
			// maximum widths. Full provider details remain in memory and the archive.
			for i, p := range s.Providers {
				s.Providers[i] = localWPDTraceProvider{Label: p.Label, Kind: p.Kind, Enabled: p.Enabled, SkipCode: p.SkipCode, Registration: p.Registration}
				s.ProviderDetailsOmitted++
			}
			continue
		}
		if n < 0 {
			return b, e
		} // Fixed scalar fields have a separate budget test.
		s.FirstDecoded[n] = localWPDTraceEvent{}
		s.DecodedOmitted++
	}
}

// Exact installed definitions captured on Windows in 0.10.35. These are
// manifest properties, not payload samples or inferred ETW event opcodes.
func wpdMTPCommandDefinition(id uint16) (wpdManifestFields, uint16) {
	f := wpdManifestFields{
		{"SessionID", 8, 8, 0, 1, 4},
		{"TransactionID", 8, 8, 0, 1, 4},
		{"MTP_Opcode", 6, 6, 0, 1, 2},
		{"MTP_Command_Param_count", 8, 8, 0, 1, 4},
		{"MTP_Command_Params", 8, 8, 4, 3, 4},
	}
	if id == 2000 {
		return f, 5
	}
	if id != 2001 {
		return wpdManifestFields{}, 0
	}
	f[5] = wpdManifestField{"MTP_Response_Retrieval_HR_From_Transport", 8, 8, 0, 1, 4}
	f[6] = wpdManifestField{"MTP_Response_Code", 6, 6, 0, 1, 2}
	f[7] = wpdManifestField{"MTP_Response_Param_count", 8, 8, 0, 1, 4}
	f[8] = wpdManifestField{"MTP_Response_Params", 8, 8, 4, 7, 4}
	f[9] = wpdManifestField{"MTP_Data_Length", 8, 8, 0, 1, 4}
	f[10] = wpdManifestField{"MTP_Data_Buffer", 14, 15, 2, 1, 9}
	return f, 11
}
func wpdExactMTPCommandField(provider string, id uint16, version uint8, metadata []byte) []wpdTraceNumericField {
	if provider != "mtp" || version != 0 || len(metadata) < 112 || binary.LittleEndian.Uint16(metadata[32:]) != id || metadata[34] != version {
		return nil
	}
	want, count := wpdMTPCommandDefinition(id)
	if count == 0 {
		return nil
	}
	got, n, top, stage := wpdManifestDefinition(metadata)
	if stage != "complete" || n != count || top != count || got != want {
		return nil
	}
	return []wpdTraceNumericField{{Name: "MTP_Opcode", Size: 2}}
}
func wpdDecodedCommandRole(e localWPDTraceEvent) string {
	if e.Provider == "mtp" && e.Version == 0 && e.CommandField == "MTP_Opcode" {
		if e.EventID == 2000 {
			return "command_context"
		}
		if e.EventID == 2001 {
			return "response_corresponding_command"
		}
	}
	return "event_scalar"
}

func wpdDecodeCommandValues(fields []wpdTraceNumericField, strictResponse bool, size func(string) (uint32, uint32), read func(string, uint32) (uint64, uint32)) (string, uint64, string, uint32, wpdMTPResponse) {
	field, value, stage, code := wpdTraceDecodeFields(fields, size, read)
	var response wpdMTPResponse
	if stage != "decoded" || field != "MTP_Opcode" || !strictResponse {
		return field, value, stage, code, response
	}
	_, v, s, c := wpdTraceDecodeFields([]wpdTraceNumericField{{"MTP_Response_Code", 2}}, size, read)
	response.CodeRead = s == "decoded"
	response.CodeNative = c
	if response.CodeRead {
		response.Code = uint16(v)
	} else {
		response.CodeError = s
	}
	_, v, s, c = wpdTraceDecodeFields([]wpdTraceNumericField{{"MTP_Response_Retrieval_HR_From_Transport", 4}}, size, read)
	response.TransportRead = s == "decoded"
	response.TransportNative = c
	if response.TransportRead {
		response.TransportHR = uint32(v)
	} else {
		response.TransportError = s
	}
	return field, value, stage, code, response
}

// Installed manifest definitions contain no event values. Count and Length
// retain the raw union values: flags 2/4 mean property indices, not sizes.
type wpdManifestField struct {
	Name            string
	InType, OutType uint16
	Flags           uint32
	Count, Length   uint16
}

func (f wpdManifestField) MarshalJSON() ([]byte, error) {
	return json.Marshal([6]any{f.Name, f.InType, f.OutType, f.Flags, f.Count, f.Length})
}

type wpdManifestFields [16]wpdManifestField

func (f wpdManifestFields) MarshalJSON() ([]byte, error) {
	n := 0
	for n < len(f) && f[n].Name != "" {
		n++
	}
	return json.Marshal(f[:n])
}

type wpdManifestTemplate struct {
	Provider   string            `json:"provider"`
	EventID    uint16            `json:"event_id"`
	Version    uint8             `json:"version"`
	Source     string            `json:"source"`
	Stage      string            `json:"stage"`
	NativeCode uint32            `json:"native_code,omitempty"`
	Complete   bool              `json:"complete"`
	Properties uint16            `json:"properties"`
	Top        uint16            `json:"top"`
	Fields     wpdManifestFields `json:"fields"`
}
type wpdManifestTemplates [4]wpdManifestTemplate

func (s wpdManifestTemplates) MarshalJSON() ([]byte, error) {
	n := 0
	for n < len(s) && s[n].Provider != "" {
		n++
	}
	return json.Marshal(s[:n])
}

var wpdManifestTargets = [4]struct {
	Provider int
	ID       uint16
}{{1, 2001}, {2, 100}, {1, 2000}, {1, 2004}}

const wpdManifestSource = "installed_manifest_no_event_values"

// Enumerate returns canonical descriptors; never invent keyword/opcode fields.
func wpdManifestDescriptor(b []byte, id uint16) ([16]byte, string) {
	var out [16]byte
	if len(b) < 8 || len(b) > 65536 {
		return out, "enumeration_invalid"
	}
	n := binary.LittleEndian.Uint32(b)
	if uint64(n)*16+8 > uint64(len(b)) {
		return out, "enumeration_invalid"
	}
	found := false
	for i := uint32(0); i < n; i++ {
		v := b[8+i*16 : 8+(i+1)*16]
		if binary.LittleEndian.Uint16(v) != id || v[2] != 0 {
			continue
		}
		if found {
			return [16]byte{}, "descriptor_ambiguous"
		}
		copy(out[:], v)
		found = true
	}
	if !found {
		return out, "event_unavailable"
	}
	return out, ""
}
func wpdManifestName(b []byte, offset uint32, minimum uint64) string {
	if uint64(offset) < minimum || offset%2 != 0 || uint64(offset) >= uint64(len(b)) {
		return ""
	}
	var name [48]byte
	for i := 0; i <= len(name); i++ {
		p := uint64(offset) + uint64(i)*2
		if p+2 > uint64(len(b)) {
			return ""
		}
		v := binary.LittleEndian.Uint16(b[p : p+2])
		if v == 0 {
			if i == 0 {
				return ""
			}
			return string(name[:i])
		}
		if i == len(name) || !(v == '_' || v >= 'A' && v <= 'Z' || v >= 'a' && v <= 'z' || i > 0 && v >= '0' && v <= '9') {
			return ""
		}
		name[i] = byte(v)
	}
	return ""
}
func wpdManifestDefinition(b []byte) (wpdManifestFields, uint16, uint16, string) {
	var empty, fields wpdManifestFields
	if len(b) < 112 || len(b) > 65536 || binary.LittleEndian.Uint32(b[48:]) != 0 {
		return empty, 0, 0, "metadata_invalid"
	}
	n, top := binary.LittleEndian.Uint32(b[100:]), binary.LittleEndian.Uint32(b[104:])
	if n > 256 || top > n || uint64(n)*24+112 > uint64(len(b)) {
		return empty, 0, 0, "metadata_invalid"
	}
	if n > 16 {
		return empty, uint16(n), uint16(top), "field_limit"
	}
	if top != n {
		return empty, uint16(n), uint16(top), "unsupported_layout"
	}
	minimum := uint64(n)*24 + 112
	for i := uint32(0); i < n; i++ {
		p := b[112+i*24 : 112+(i+1)*24]
		flags := binary.LittleEndian.Uint32(p)
		// Struct/custom schema changes the union layout. Do not label its
		// indices as scalar types, or export a partially decoded template.
		if flags & ^uint32(0x7e) != 0 {
			return empty, uint16(n), uint16(top), "unsupported_layout"
		}
		name := wpdManifestName(b, binary.LittleEndian.Uint32(p[4:]), minimum)
		if name == "" {
			return empty, uint16(n), uint16(top), "invalid_property_name"
		}
		for j := uint32(0); j < i; j++ {
			if fields[j].Name == name {
				return empty, uint16(n), uint16(top), "invalid_property_name"
			}
		}
		count, length := binary.LittleEndian.Uint16(p[16:]), binary.LittleEndian.Uint16(p[18:])
		if flags&4 != 0 && uint32(count) >= n || flags&2 != 0 && uint32(length) >= n {
			return empty, uint16(n), uint16(top), "invalid_property_reference"
		}
		fields[i] = wpdManifestField{name, binary.LittleEndian.Uint16(p[8:]), binary.LittleEndian.Uint16(p[10:]), flags, count, length}
	}
	return fields, uint16(n), uint16(top), "complete"
}

func wpdTraceUTF16(b []byte, offset uint32, limit int) string {
	if offset%2 != 0 || int(offset) >= len(b) {
		return ""
	}
	u := make([]uint16, 0, limit)
	for i := int(offset); i+1 < len(b) && len(u) <= limit; i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			return string(utf16.Decode(u))
		}
		u = append(u, v)
	}
	return ""
}

// Schema summaries contain metadata categories only, never property names or
// event payload. A value array keeps controller snapshots independent.
type localWPDTraceSchema struct {
	Provider    string `json:"provider"`
	EventID     uint16 `json:"event_id"`
	Version     uint8  `json:"version"`
	HeaderFlags uint16 `json:"header_flags"`
	DataLength  uint16 `json:"data_length"`
	Stage       string `json:"stage"`
	NativeCode  uint32 `json:"native_code,omitempty"`
	localWPDTraceSchemaInfo
}
type localWPDTraceSchemaInfo struct {
	Source     string `json:"source,omitempty"`
	Properties uint16 `json:"properties,omitempty"`
	Top        uint16 `json:"top,omitempty"`
	Candidates uint8  `json:"candidates,omitempty"`
	// These independent counts describe top-level properties; they can overlap.
	OtherNames uint16 `json:"other_names,omitempty"`
	Flagged    uint16 `json:"flagged,omitempty"`
	Structs    uint16 `json:"structs,omitempty"`
	Arrays     uint16 `json:"arrays,omitempty"`
	Binary     uint16 `json:"binary,omitempty"`
	OtherTypes uint16 `json:"other_types,omitempty"`
}
type localWPDTraceSchemas [8]localWPDTraceSchema

func (s localWPDTraceSchemas) MarshalJSON() ([]byte, error) {
	n := 0
	for n < len(s) && s[n].Provider != "" {
		n++
	}
	return json.Marshal(s[:n])
}

type localWPDTraceDecodeCounts struct {
	Attempted       uint64 `json:"attempted"`
	MetadataFailed  uint64 `json:"metadata_failed,omitempty"`
	InvalidMetadata uint64 `json:"metadata_invalid,omitempty"`
	NoCandidate     uint64 `json:"no_candidate,omitempty"`
	SizeFailed      uint64 `json:"size_failed,omitempty"`
	SizeMismatch    uint64 `json:"size_mismatch,omitempty"`
	ReadFailed      uint64 `json:"read_failed,omitempty"`
}

func (s *localWPDTraceSample) recordDecode(d localWPDTraceSchema) {
	s.DecodeCounts.Attempted++
	switch d.Stage {
	case "metadata_size_failed", "metadata_read_failed":
		s.DecodeCounts.MetadataFailed++
	case "metadata_invalid", "strict_manifest_template_mismatch", "header_flags_unsupported", "header_size_invalid", "extended_data_unsupported":
		s.DecodeCounts.InvalidMetadata++
	case "no_candidate", "provider_unproven", "event_not_selected", "version_not_selected":
		s.DecodeCounts.NoCandidate++
	case "size_failed", "payload_size_invalid":
		s.DecodeCounts.SizeFailed++
	case "size_mismatch", "payload_layout_invalid":
		s.DecodeCounts.SizeMismatch++
	case "read_failed":
		s.DecodeCounts.ReadFailed++
	}
	s.recordSchema(d)
}

func (s *localWPDTraceSample) recordSchema(d localWPDTraceSchema) {
	for i := range s.Schemas {
		old := s.Schemas[i]
		if old.Provider == d.Provider && old.EventID == d.EventID && old.Version == d.Version {
			if old.Stage == "header_only_rate_limited" && d.Stage != "header_only_rate_limited" {
				s.Schemas[i] = d
			}
			return
		}
		if old.Provider == "" {
			s.Schemas[i] = d
			return
		}
	}
	s.SchemaUnretainedEvents++
}

// The callback holds its state lock across admission. Rejected events may
// retain fixed headers, but must never perform a TDH or payload read.
type wpdCriticalEventCounts struct {
	Seen    uint64 `json:"seen"`
	Parsed  uint64 `json:"parsed"`
	Skipped uint64 `json:"skipped"`
}

type wpdCriticalSampling [2]wpdCriticalEventCounts

func (s wpdCriticalSampling) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Unit   string                 `json:"unit"`
		Scope  string                 `json:"scope"`
		Parsed string                 `json:"parsed_semantics"`
		Begin  wpdCriticalEventCounts `json:"mtp2000_v0"`
		End    wpdCriticalEventCounts `json:"mtp2001_v0"`
	}{"etw_events", "system_unattributed", "admitted_not_success", s[0], s[1]})
}

func (s *wpdCriticalEventCounts) record(admitted bool) {
	// Freeze the triple together at saturation so Seen == Parsed + Skipped.
	if s.Seen == ^uint64(0) {
		return
	}
	s.Seen++
	if admitted {
		s.Parsed++
	} else {
		s.Skipped++
	}
}

type wpdTraceSamplingGate struct {
	second  int64
	count   int
	general int
}

func (g *wpdTraceSamplingGate) admit(second int64, s *localWPDTraceSample, header localWPDTraceSchema) bool {
	if g.second != second {
		g.second = second
		g.count = 0
		g.general = 0
	}
	critical := header.Provider == "mtp" && header.Version == 0 && (header.EventID == 2000 || header.EventID == 2001)
	// Ordinary events may use four slots; the remaining twelve cannot be
	// consumed by USB/API noise. Critical events may use all unused slots.
	admitted := g.count < 16 && (critical || g.general < 4)
	if critical {
		s.CriticalSampling[header.EventID-2000].record(admitted)
	}
	if admitted {
		g.count++
		if !critical {
			g.general++
		}
		return true
	}
	s.SampledOut++
	switch header.Provider {
	case "api", "mtp", "usb":
		s.HeaderOnlyEvents++
		s.recordSchema(localWPDTraceSchema{Provider: header.Provider, EventID: header.EventID, Version: header.Version, HeaderFlags: header.HeaderFlags, DataLength: header.DataLength, Stage: "header_only_rate_limited"})
	}
	return false
}

type wpdTraceNumericField struct {
	Name string
	Size uint32
}

// Preserve the original allowlist and scalar restrictions. Diagnostic counts
// must not cause any additional property to be read.
func wpdTraceInspectMetadata(b []byte) ([]wpdTraceNumericField, localWPDTraceSchemaInfo, bool) {
	var out []wpdTraceNumericField
	var info localWPDTraceSchemaInfo
	if len(b) < 112 || len(b) > 65536 {
		return out, info, false
	}
	count := binary.LittleEndian.Uint32(b[100:])
	top := binary.LittleEndian.Uint32(b[104:])
	if count > 256 || top > count || 112+uint64(count)*24 > uint64(len(b)) {
		return out, info, false
	}
	info.Properties, info.Top = uint16(count), uint16(top)
	switch binary.LittleEndian.Uint32(b[48:]) {
	case 0:
		info.Source = "manifest"
	case 1:
		info.Source = "wbem"
	case 2:
		info.Source = "wpp"
	case 3:
		info.Source = "tracelogging"
	default:
		info.Source = "unknown"
	}
	for i := uint32(0); i < top; i++ {
		p := b[112+i*24:]
		flags := binary.LittleEndian.Uint32(p)
		count := binary.LittleEndian.Uint16(p[16:])
		if flags != 0 {
			info.Flagged++
		}
		if flags&1 != 0 {
			info.Structs++
		}
		if count != 1 || flags&(4|32) != 0 {
			info.Arrays++
		}
		kind := binary.LittleEndian.Uint16(p[8:])
		var size uint32
		if flags&1 == 0 {
			switch kind {
			case 4:
				size = 1
			case 6:
				size = 2
			case 8, 20:
				size = 4
			case 10, 21:
				size = 8
			default:
				info.OtherTypes++
			}
			if kind == 14 {
				info.Binary++
			}
		}
		name := wpdTraceUTF16(b, binary.LittleEndian.Uint32(p[4:]), 32)
		matched := false
		switch name {
		case "MTPOpcode", "MtpOpcode", "OperationCode", "ResponseCode", "CommandId":
			matched = true
		}
		if !matched {
			info.OtherNames++
		}
		if matched && flags == 0 && count == 1 && size != 0 && len(out) < 5 {
			out = append(out, wpdTraceNumericField{name, size})
		}
	}
	info.Candidates = uint8(len(out))
	return out, info, true
}
func wpdTraceNumericProperties(b []byte) []wpdTraceNumericField {
	out, _, _ := wpdTraceInspectMetadata(b)
	return out
}

// All candidates are still tried. If none succeeds, the first native failure
// is retained, so later candidates cannot erase the original failure code.
func wpdTraceDecodeFields(fields []wpdTraceNumericField, size func(string) (uint32, uint32), read func(string, uint32) (uint64, uint32)) (string, uint64, string, uint32) {
	stage, code := "no_candidate", uint32(0)
	for _, f := range fields {
		n, r := size(f.Name)
		failure := ""
		if r != 0 {
			failure = "size_failed"
		} else if n != f.Size || n > 8 {
			failure = "size_mismatch"
		}
		if failure == "" {
			value, readCode := read(f.Name, n)
			if readCode == 0 {
				return f.Name, value, "decoded", 0
			}
			failure, r = "read_failed", readCode
		}
		if stage == "no_candidate" {
			stage, code = failure, r
		}
	}
	return "", 0, stage, code
}

// TRACE_PROVIDER_FLAG_LEGACY (1) identifies RegisterTraceGuids; modern
// EventRegister providers can be enabled to several sessions. PRE_ENABLE (2)
// alone cannot establish which registration API a future instance will use.
func wpdTraceProviderUnusedMetadata(b []byte) localWPDTraceProvider {
	out := localWPDTraceProvider{Kind: "unknown", SkipCode: "metadata_invalid", Registration: "metadata_invalid"}
	if len(b) < 8 {
		return out
	}
	count := binary.LittleEndian.Uint32(b)
	offset := uint64(8)
	if count > 1024 {
		return out
	}
	out.InstanceCount = count
	if count == 0 {
		out.SkipCode = "type_unknown"
		out.Registration = "no_instances"
		return out
	}
	modern, legacy, unknown := false, false, false
	preEnabled, unknownFlags, invalidEnable := false, false, false
	loggers := map[uint16]bool{}
	for i := uint32(0); i < count; i++ {
		if offset+16 > uint64(len(b)) {
			return out
		}
		p := b[offset:]
		next := binary.LittleEndian.Uint32(p)
		enabled := binary.LittleEndian.Uint32(p[4:])
		flags := binary.LittleEndian.Uint32(p[12:])
		out.FlagsOR |= flags
		blockSize := uint64(16) + uint64(enabled)*32
		if blockSize > uint64(len(p)) {
			return out
		}
		if i+1 < count {
			if uint64(next) < blockSize || offset+uint64(next) >= uint64(len(b)) {
				return out
			}
		} else if next != 0 {
			return out
		}
		if flags&^uint32(3) != 0 {
			unknown = true
			unknownFlags = true
			out.UnknownInstances++
		} else if flags&2 != 0 {
			preEnabled = true
			out.PreEnabledInstances++
		} else if flags&1 != 0 {
			legacy = true
			out.LegacyInstances++
		} else {
			modern = true
			out.ModernInstances++
		}
		for n := uint32(0); n < enabled; n++ {
			entry := p[16+uint64(n)*32:]
			switch binary.LittleEndian.Uint32(entry) {
			case 0:
				continue
			case 1:
			default:
				unknown = true
				invalidEnable = true
				continue
			}
			loggers[binary.LittleEndian.Uint16(entry[6:])] = true
		}
		if i+1 < count {
			offset += uint64(next)
		}
	}
	out.OtherLoggerCount = uint32(len(loggers))
	out.SkipCode = ""
	out.Registration = "registered"
	switch {
	case invalidEnable:
		out.Registration = "invalid_enable_value"
	case unknownFlags:
		out.Registration = "unknown_flags"
	case preEnabled && (modern || legacy):
		out.Registration = "registered_with_pre_enable"
	case preEnabled:
		out.Registration = "pre_enabled"
	}
	switch {
	case unknown:
		out.Kind = "unknown"
		out.SkipCode = "type_unknown"
	case legacy && modern:
		out.Kind = "mixed"
	case legacy:
		out.Kind = "legacy"
	case modern:
		out.Kind = "modern"
	default:
		out.SkipCode = "type_unknown"
	}
	// PRE_ENABLE is a placeholder, not evidence of a registration API. It
	// cannot conceal real instances or authorize a provider on its own. With
	// any live classic instance, even a placeholder's active logger is reason
	// to refuse rather than risk redirecting that provider's single session.
	if legacy && len(loggers) > 0 && !unknown {
		out.SkipCode = "legacy_in_use"
	}
	return out
}
