//go:build usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestLocalWPDTraceSchemaCategoriesNeverReadUnknownFields(t *testing.T) {
	type property struct {
		name  string
		kind  uint16
		flags uint32
		count uint16
	}
	properties := []property{
		{"MTPOpcode", 6, 0, 1}, {"SECRET_device_path", 14, 0, 1},
		{"CommandId", 8, 1, 1}, {"ResponseCode", 6, 32, 1},
		{"OperationCode", 8, 0, 2}, {"MtpOpcode", 1, 0, 1},
		{"CommandId", 8, 64, 1},
	}
	b := make([]byte, 112+24*len(properties))
	binary.LittleEndian.PutUint32(b[100:], uint32(len(properties)))
	binary.LittleEndian.PutUint32(b[104:], uint32(len(properties)))
	for i, p := range properties {
		off := 112 + 24*i
		binary.LittleEndian.PutUint32(b[off:], p.flags)
		binary.LittleEndian.PutUint32(b[off+4:], uint32(len(b)))
		binary.LittleEndian.PutUint16(b[off+8:], p.kind)
		binary.LittleEndian.PutUint16(b[off+16:], p.count)
		for _, v := range utf16.Encode([]rune(p.name + "\x00")) {
			b = binary.LittleEndian.AppendUint16(b, v)
		}
	}
	fields, info, valid := wpdTraceInspectMetadata(b)
	if !valid || len(fields) != 1 || fields[0].Name != "MTPOpcode" || info.Source != "manifest" || info.Properties != 7 || info.Top != 7 || info.Candidates != 1 || info.OtherNames != 1 || info.Flagged != 3 || info.Structs != 1 || info.Arrays != 2 || info.Binary != 1 || info.OtherTypes != 2 {
		t.Fatal(fields, info, valid)
	}
	output, _ := json.Marshal(info)
	if strings.Contains(string(output), "SECRET") || strings.Contains(string(output), "MTPOpcode") {
		t.Fatal(string(output))
	}
	for source, want := range []string{"manifest", "wbem", "wpp", "tracelogging", "unknown"} {
		binary.LittleEndian.PutUint32(b[48:], uint32(source))
		_, info, ok := wpdTraceInspectMetadata(b)
		if !ok || info.Source != want {
			t.Fatal(source, info)
		}
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:111] },
		func(b []byte) []byte { binary.LittleEndian.PutUint32(b[100:], 257); return b },
		func(b []byte) []byte { binary.LittleEndian.PutUint32(b[104:], 8); return b },
		func(b []byte) []byte { return b[:112] },
		func(b []byte) []byte { return make([]byte, 65537) },
	} {
		fields, _, ok := wpdTraceInspectMetadata(mutate(append([]byte(nil), b...)))
		if ok || len(fields) != 0 {
			t.Fatal("invalid schema accepted")
		}
	}
}

func TestLocalWPDTraceDecodeFailuresAndLaterSuccess(t *testing.T) {
	fields := []wpdTraceNumericField{{"MTPOpcode", 2}, {"ResponseCode", 2}}
	for _, tc := range []struct {
		stage                string
		size, code, readCode uint32
		wantRead             bool
	}{
		{"size_failed", 2, 1168, 0, false}, {"size_mismatch", 4, 0, 0, false},
		{"size_mismatch", 9, 0, 0, false}, {"read_failed", 2, 0, 5, true}, {"decoded", 2, 0, 0, true},
	} {
		reads := 0
		name, value, stage, code := wpdTraceDecodeFields(fields, func(string) (uint32, uint32) { return tc.size, tc.code }, func(string, uint32) (uint64, uint32) { reads++; return 0x1001, tc.readCode })
		wantCode := tc.code
		if tc.readCode != 0 {
			wantCode = tc.readCode
		}
		if stage != tc.stage || code != wantCode || (reads > 0) != tc.wantRead {
			t.Fatal(tc, stage, code, reads)
		}
		if stage == "decoded" {
			if name != "MTPOpcode" || value != 0x1001 {
				t.Fatal(name, value)
			}
		} else if name != "" || value != 0 {
			t.Fatal("failure published a command")
		}
	}
	name, _, stage, code := wpdTraceDecodeFields(fields, func(name string) (uint32, uint32) {
		if name == "MTPOpcode" {
			return 0, 5
		}
		return 2, 0
	}, func(string, uint32) (uint64, uint32) { return 0x2001, 0 })
	if name != "ResponseCode" || stage != "decoded" || code != 0 {
		t.Fatal(name, stage, code)
	}
	_, _, stage, code = wpdTraceDecodeFields(fields, func(name string) (uint32, uint32) {
		if name == "MTPOpcode" {
			return 0, 5
		}
		return 2, 0
	}, func(string, uint32) (uint64, uint32) { return 0, 1168 })
	if stage != "size_failed" || code != 5 {
		t.Fatal("first failure lost", stage, code)
	}
	_, _, stage, _ = wpdTraceDecodeFields(nil, func(string) (uint32, uint32) { t.Fatal("no candidate queried"); return 0, 0 }, nil)
	if stage != "no_candidate" {
		t.Fatal(stage)
	}
}

func TestLocalWPDTraceFirstDistinctSchemasSurviveRepeatsAndSnapshots(t *testing.T) {
	c := newLocalWPDTraceController()
	for i := 0; i < 8; i++ {
		c.state.recordDecode(localWPDTraceSchema{Provider: "mtp", EventID: uint16(i / 2), Version: uint8(i % 2), Stage: "no_candidate"})
	}
	for i := 0; i < 20; i++ {
		c.state.recordDecode(localWPDTraceSchema{Provider: "mtp", EventID: 0, Stage: "read_failed", NativeCode: 5})
	}
	c.state.recordDecode(localWPDTraceSchema{Provider: "usb", EventID: 999, Stage: "metadata_size_failed", NativeCode: 1168})
	a := c.snapshot()
	a.Schemas[0].Stage = "changed"
	b := c.snapshot()
	if b.Schemas[0].Stage != "no_candidate" || b.Schemas[7].EventID != 3 || b.Schemas[7].Version != 1 || b.SchemaUnretainedEvents != 1 || b.DecodeCounts.Attempted != 29 || b.DecodeCounts.NoCandidate != 8 || b.DecodeCounts.ReadFailed != 20 || b.DecodeCounts.MetadataFailed != 1 {
		t.Fatal(b)
	}
	for _, stage := range []string{"metadata_read_failed", "metadata_invalid", "size_failed", "size_mismatch", "decoded"} {
		b.recordDecode(localWPDTraceSchema{Provider: "mtp", Stage: stage})
	}
	if b.DecodeCounts.MetadataFailed != 2 || b.DecodeCounts.InvalidMetadata != 1 || b.DecodeCounts.SizeFailed != 1 || b.DecodeCounts.SizeMismatch != 1 {
		t.Fatal(b.DecodeCounts)
	}
}

func TestLocalWPDTraceSchemaAndStatusByteBudget(t *testing.T) {
	c := newLocalWPDTraceController()
	s := c.snapshot()
	s.RequestID = strings.Repeat("a", 32)
	s.RejectedID = strings.Repeat("b", 32)
	s.RejectedError = "WPD_TRACE_DEBUG_REQUIRED"
	s.Phase = "waiting_provider_registration"
	s.Persistence = "failed"
	s.Error = "WPD_TRACE_RECOVERY_FAILED"
	s.CauseCode = "WPD_TRACE_PROVIDER_METADATA_INVALID"
	s.NativeCode = ^uint32(0)
	s.RunID = strings.Repeat("a", 32)
	s.SampledUTC = "2026-10-17T12:23:34.123456789Z"
	s.SampledMS = 9223372036854775807
	s.Events = ^uint64(0)
	s.Decoded = ^uint64(0)
	s.SampledOut = ^uint64(0)
	s.Unmapped = ^uint64(0)
	s.EventsLost = ^uint32(0)
	s.SchemaUnretainedEvents = ^uint64(0)
	s.HeaderOnlyEvents = ^uint64(0)
	s.DecodeCounts = localWPDTraceDecodeCounts{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	for i := range s.Providers {
		s.Providers[i] = localWPDTraceProvider{Label: "api", Kind: "unknown", OtherLoggerCount: ^uint32(0), Enabled: true, EnabledUTC: s.SampledUTC, SkipCode: "invalid_enable_value", NativeCode: ^uint32(0), Registration: "registered_with_pre_enable", InstanceCount: 1024, FlagsOR: ^uint32(0), Schema: "tracelogging", ModernInstances: 1024, LegacyInstances: 1024, PreEnabledInstances: 1024, UnknownInstances: 1024}
	}
	for i := 0; i < 8; i++ {
		s.Recent = append(s.Recent, localWPDTraceEvent{Provider: "mtp", EventID: 65535, PID: ^uint32(0), Task: 65535, ETWOpcode: 255, MS: 9223372036854775807, EventUTC: s.SampledUTC, OpcodeDecoded: true, CommandField: "OperationCode", CommandCode: ^uint64(0)})
		s.Schemas[i] = localWPDTraceSchema{Provider: "mtp", EventID: uint16(i), Version: 255, HeaderFlags: 65535, DataLength: 65535, Stage: "header_only_rate_limited", NativeCode: ^uint32(0), localWPDTraceSchemaInfo: localWPDTraceSchemaInfo{Source: "tracelogging", Properties: 256, Top: 256, Candidates: 5, OtherNames: 256, Flagged: 256, Structs: 256, Arrays: 256, Binary: 256, OtherTypes: 256}}
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > 4096 {
		t.Fatal(len(b), e)
	}
	var wire struct {
		Schemas        []localWPDTraceSchema `json:"schemas"`
		SchemasOmitted int                   `json:"schemas_omitted"`
		RecentOmitted  int                   `json:"recent_omitted"`
	}
	if json.Unmarshal(b, &wire) != nil || len(wire.Schemas) == 0 || len(wire.Schemas)+wire.SchemasOmitted != 8 || wire.RecentOmitted == 0 {
		t.Fatal(string(b))
	}
	for i, v := range wire.Schemas {
		if v.EventID != uint16(i) {
			t.Fatal("first schemas replaced")
		}
	}
	if s.Schemas[7].Provider != "mtp" || len(s.Recent) != 8 || s.SchemasOmitted != 0 {
		t.Fatal("serialization mutated snapshot")
	}
	envelope, _ := json.Marshal(struct {
		Version string              `json:"core_version"`
		WPD     localWPDTraceStatus `json:"wpd_trace"`
	}{"0.10.33", s})
	if len(envelope) > 4200 {
		t.Fatal(len(envelope))
	}
	t.Logf("WPD status=%d envelope=%d retained schemas=%d", len(b), len(envelope), len(wire.Schemas))
}

func TestLocalWPDTraceRateLimitRetainsNewHeaderWithoutTDH(t *testing.T) {
	var gate wpdTraceSamplingGate
	var sample localWPDTraceSample
	tdhCalls := 0
	deliver := func(second int64, header localWPDTraceSchema) {
		if !gate.admit(second, &sample, header) {
			return
		}
		tdhCalls++
		header.Stage = "no_candidate"
		header.localWPDTraceSchemaInfo = localWPDTraceSchemaInfo{Source: "manifest", Properties: 2, Top: 2, OtherNames: 2}
		sample.recordDecode(header)
	}
	// A burst of one repeated type must not hide the next distinct header.
	for i := 0; i < 16; i++ {
		deliver(100, localWPDTraceSchema{Provider: "mtp", EventID: 2000})
	}
	newHeader := localWPDTraceSchema{Provider: "mtp", EventID: 2003, Version: 2, HeaderFlags: 0x40, DataLength: 48}
	deliver(100, newHeader)
	if tdhCalls != 16 || sample.DecodeCounts.Attempted != 16 || sample.SampledOut != 1 || sample.HeaderOnlyEvents != 1 || sample.Schemas[1].EventID != 2003 || sample.Schemas[1].Version != 2 || sample.Schemas[1].HeaderFlags != 0x40 || sample.Schemas[1].DataLength != 48 || sample.Schemas[1].Stage != "header_only_rate_limited" || sample.Schemas[1].Source != "" {
		t.Fatal(tdhCalls, sample)
	}
	// A copied snapshot must not change when a deferred type is finally decoded.
	before := sample
	deliver(101, newHeader)
	if tdhCalls != 17 || sample.DecodeCounts.Attempted != 17 || sample.Schemas[1].Stage != "no_candidate" || sample.Schemas[1].Source != "manifest" || before.Schemas[1].Stage != "header_only_rate_limited" {
		t.Fatal(tdhCalls, sample)
	}
	for i := 0; i < 15; i++ {
		deliver(101, localWPDTraceSchema{Provider: "mtp", EventID: 2000})
	}
	deliver(101, newHeader)
	if tdhCalls != 32 || sample.Schemas[1].Stage != "no_candidate" || sample.HeaderOnlyEvents != 2 || sample.DecodeCounts.Attempted != 32 {
		t.Fatal(tdhCalls, sample)
	}
	sample.recordDecode(localWPDTraceSchema{Provider: "mtp", EventID: 2003, Version: 2, Stage: "read_failed", NativeCode: 5})
	if sample.Schemas[1].Stage != "no_candidate" {
		t.Fatal("complete first summary overwritten")
	}
	wire, e := json.Marshal(localWPDTraceStatus{localWPDTraceSample: before})
	if e != nil || !strings.Contains(string(wire), "header_only_rate_limited") {
		t.Fatal(string(wire), e)
	}
}

func TestLocalWPDTraceLimitedUnknownAndFullSchemaCapacity(t *testing.T) {
	gate := wpdTraceSamplingGate{second: 100, count: 16}
	var sample localWPDTraceSample
	for i := 0; i < 8; i++ {
		if gate.admit(100, &sample, localWPDTraceSchema{Provider: "api", EventID: uint16(i)}) {
			t.Fatal("TDH admitted after budget")
		}
	}
	first := sample.Schemas
	if gate.admit(100, &sample, localWPDTraceSchema{Provider: "mtp", EventID: 999}) {
		t.Fatal("extra TDH")
	}
	if sample.SchemaUnretainedEvents != 1 || sample.HeaderOnlyEvents != 9 || sample.SampledOut != 9 || sample.DecodeCounts.Attempted != 0 || first != sample.Schemas {
		t.Fatal(sample)
	}
	// Unknown providers do not acquire a made-up label or enter the schema ring.
	if gate.admit(100, &sample, localWPDTraceSchema{Provider: "SECRET", EventID: 999}) {
		t.Fatal("extra TDH")
	}
	if sample.SchemaUnretainedEvents != 1 || sample.HeaderOnlyEvents != 9 || sample.SampledOut != 10 || sample.DecodeCounts.Attempted != 0 || first != sample.Schemas {
		t.Fatal(sample)
	}
	// An existing deferred slot can upgrade even with a full ring.
	if !gate.admit(101, &sample, localWPDTraceSchema{Provider: "api", EventID: 7}) {
		t.Fatal("new second blocked")
	}
	sample.recordDecode(localWPDTraceSchema{Provider: "api", EventID: 7, Stage: "metadata_read_failed", NativeCode: 1168})
	if sample.Schemas[7].Stage != "metadata_read_failed" || sample.SchemaUnretainedEvents != 1 || sample.DecodeCounts.Attempted != 1 {
		t.Fatal(sample)
	}
	// Oversized classification/payload fields never ride along with a header.
	var clean localWPDTraceSample
	gate = wpdTraceSamplingGate{second: 100, count: 16}
	gate.admit(100, &clean, localWPDTraceSchema{Provider: "api", Stage: "SECRET", NativeCode: 5, localWPDTraceSchemaInfo: localWPDTraceSchemaInfo{Source: "SECRET"}})
	b, _ := json.Marshal(clean.Schemas)
	if strings.Contains(string(b), "SECRET") || clean.Schemas[0].NativeCode != 0 {
		t.Fatal(string(b))
	}
}
