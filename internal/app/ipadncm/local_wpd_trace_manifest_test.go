//go:build usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func manifestFixture(fields []wpdManifestField) []byte {
	b := make([]byte, 112+24*len(fields))
	binary.LittleEndian.PutUint32(b[100:], uint32(len(fields)))
	binary.LittleEndian.PutUint32(b[104:], uint32(len(fields)))
	for i, f := range fields {
		p := b[112+24*i:]
		binary.LittleEndian.PutUint32(p, f.Flags)
		binary.LittleEndian.PutUint32(p[4:], uint32(len(b)))
		binary.LittleEndian.PutUint16(p[8:], f.InType)
		binary.LittleEndian.PutUint16(p[10:], f.OutType)
		binary.LittleEndian.PutUint16(p[16:], f.Count)
		binary.LittleEndian.PutUint16(p[18:], f.Length)
		for _, v := range f.Name {
			b = append(b, byte(v), byte(v>>8))
		}
		b = append(b, 0, 0)
	}
	return b
}
func TestWPDManifestDefinitionRetainsStaticUnions(t *testing.T) {
	want := []wpdManifestField{{"ByteCount", 8, 0, 0, 1, 0}, {"ParameterCount", 6, 0, 0, 1, 0}, {"CommandData", 14, 15, 2, 1, 0}, {"Parameters", 8, 0, 4, 1, 0}}
	f, n, top, stage := wpdManifestDefinition(manifestFixture(want))
	if stage != "complete" || n != 4 || top != 4 {
		t.Fatal(n, top, stage)
	}
	for i, v := range want {
		if f[i] != v {
			t.Fatal(f[i], v)
		}
	}
	wire, e := json.Marshal(f[0])
	if e != nil || string(wire) != `["ByteCount",8,0,0,1,0]` {
		t.Fatal(string(wire), e)
	}
	copy := f
	copy[0].Name = "Changed"
	if f[0].Name != "ByteCount" {
		t.Fatal("snapshot aliased")
	}
}
func TestWPDManifestDefinitionRejectsPartialOrUnsafeMetadata(t *testing.T) {
	base := func() []byte { return manifestFixture([]wpdManifestField{{"Code", 6, 0, 0, 1, 0}}) }
	cases := []struct {
		name, stage string
		edit        func([]byte) []byte
	}{
		{"bad_offset", "invalid_property_name", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[116:], 112); return b }},
		{"odd_offset", "invalid_property_name", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[116:], 137); return b }},
		{"unterminated", "invalid_property_name", func(b []byte) []byte { return b[:len(b)-2] }},
		{"non_ascii", "invalid_property_name", func(b []byte) []byte { b[137] = 1; return b }},
		{"punctuation", "invalid_property_name", func(b []byte) []byte { b[136] = '-'; return b }},
		{"struct", "unsupported_layout", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[112:], 1); return b }},
		{"custom", "unsupported_layout", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[112:], 128); return b }},
		{"count_index", "invalid_property_reference", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[112:], 4); return b }},
		{"length_index", "invalid_property_reference", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[112:], 2)
			binary.LittleEndian.PutUint16(b[130:], 1)
			return b
		}},
		{"truncated_table", "metadata_invalid", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[100:], 2); return b }},
		{"non_manifest", "metadata_invalid", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[48:], 1); return b }},
	}
	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			f, _, _, stage := wpdManifestDefinition(v.edit(base()))
			if stage != v.stage || f != (wpdManifestFields{}) {
				t.Fatal(stage, f)
			}
		})
	}
	for _, name := range []string{"", strings.Repeat("a", 49), "1Bad"} {
		f, _, _, stage := wpdManifestDefinition(manifestFixture([]wpdManifestField{{Name: name}}))
		if stage != "invalid_property_name" || f != (wpdManifestFields{}) {
			t.Fatal(name, stage)
		}
	}
	f := make([]wpdManifestField, 17)
	_, n, _, stage := wpdManifestDefinition(manifestFixture(f))
	if n != 17 || stage != "field_limit" {
		t.Fatal(n, stage)
	}
	_, _, _, stage = wpdManifestDefinition(manifestFixture([]wpdManifestField{{Name: strings.Repeat("a", 48)}}))
	if stage != "complete" {
		t.Fatal(stage)
	}
}
func TestWPDManifestCanonicalDescriptor(t *testing.T) {
	b := make([]byte, 40)
	binary.LittleEndian.PutUint32(b, 2)
	binary.LittleEndian.PutUint16(b[8:], 2001)
	b[10] = 1
	binary.LittleEndian.PutUint16(b[24:], 2001)
	b[27] = 3
	b[29] = 9
	d, s := wpdManifestDescriptor(b, 2001)
	if s != "" || d[3] != 3 || d[5] != 9 || d[2] != 0 {
		t.Fatal(d, s)
	}
	b[10] = 0
	_, s = wpdManifestDescriptor(b, 2001)
	if s != "descriptor_ambiguous" {
		t.Fatal(s)
	}
	_, s = wpdManifestDescriptor(b, 999)
	if s != "event_unavailable" {
		t.Fatal(s)
	}
	_, s = wpdManifestDescriptor(b[:39], 2001)
	if s != "enumeration_invalid" {
		t.Fatal(s)
	}
}
func TestWPDManifestBudgetAndSnapshot(t *testing.T) {
	s := newLocalWPDTraceController().snapshot()
	s.Requested, s.SavedEnabled, s.Effective = true, true, true
	s.RequestID = strings.Repeat("a", 32)
	s.RejectedID = strings.Repeat("b", 32)
	s.RejectedError = "WPD_TRACE_DEBUG_REQUIRED"
	s.Persistence = "failed"
	s.Phase = "waiting_provider_registration"
	s.Error = "WPD_TRACE_RECOVERY_FAILED"
	s.CauseCode = "WPD_TRACE_PROVIDER_METADATA_INVALID"
	s.NativeCode = ^uint32(0)
	s.RunID = strings.Repeat("a", 32)
	s.SampledUTC = "2026-10-17T12:23:34.123456789Z"
	s.SampledMS = 9223372036854775807
	s.Events, s.Decoded, s.SampledOut, s.Unmapped = ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)
	s.EventsLost = ^uint32(0)
	s.SchemaUnretainedEvents, s.HeaderOnlyEvents = ^uint64(0), ^uint64(0)
	s.DecodeCounts = localWPDTraceDecodeCounts{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	for i := range s.Providers {
		s.Providers[i] = localWPDTraceProvider{Label: "api", Kind: "unknown", OtherLoggerCount: ^uint32(0), Enabled: true, EnabledUTC: s.SampledUTC, SkipCode: "invalid_enable_value", NativeCode: ^uint32(0), Registration: "registered_with_pre_enable", InstanceCount: 1024, FlagsOR: ^uint32(0), Schema: "tracelogging", ModernInstances: 1024, LegacyInstances: 1024, PreEnabledInstances: 1024, UnknownInstances: 1024}
	}
	for i, target := range wpdManifestTargets {
		d := wpdManifestTemplate{Provider: []string{"api", "mtp", "usb"}[target.Provider], EventID: target.ID, Source: wpdManifestSource, Complete: true, Properties: 16, Top: 16, Stage: "complete"}
		for j := range d.Fields {
			d.Fields[j] = wpdManifestField{Name: strings.Repeat("x", 48), InType: 65535, OutType: 65535, Flags: 4294967295, Count: 65535, Length: 65535}
		}
		s.ManifestTemplates[i] = d
		s.Schemas[i] = localWPDTraceSchema{Provider: "usb", EventID: uint16(i), Stage: "no_candidate"}
		s.Recent = append(s.Recent, localWPDTraceEvent{Provider: "usb", EventID: uint16(i)})
	}
	before := s.ManifestTemplates
	b, e := json.Marshal(s)
	if e != nil || len(b) > 4096 {
		t.Fatal(len(b), e)
	}
	var wire struct {
		Requested, SavedEnabled, Effective bool
		RequestID                          string `json:"request_id"`
		Saved                              bool   `json:"saved_enabled"`
		Manifest                           []struct {
			EventID  uint16 `json:"event_id"`
			Complete bool
			Fields   [][6]any
		} `json:"manifest_templates"`
		Omitted        int `json:"manifest_omitted"`
		RecentOmitted  int `json:"recent_omitted"`
		SchemasOmitted int `json:"schemas_omitted"`
	}
	if json.Unmarshal(b, &wire) != nil || !wire.Requested || !wire.Effective || !wire.Saved || wire.RequestID != s.RequestID || len(wire.Manifest) == 0 || len(wire.Manifest)+wire.Omitted != 4 || wire.Omitted == 0 || wire.RecentOmitted != 4 || wire.SchemasOmitted != 4 {
		t.Fatal(string(b))
	}
	if wire.Manifest[0].EventID != 2001 {
		t.Fatal("priority template lost")
	}
	for _, d := range wire.Manifest {
		if !d.Complete || len(d.Fields) != 16 || d.Fields[15][0] == "" {
			t.Fatal("partial template", d)
		}
	}
	if s.ManifestTemplates != before || s.ManifestOmitted != 0 {
		t.Fatal("marshal mutated snapshot")
	}
	clone := s
	clone.ManifestTemplates[0].Fields[0].Name = "Changed"
	if s.ManifestTemplates != before {
		t.Fatal("shallow alias")
	}
	t.Logf("manifest-heavy status %d bytes, retained %d omitted %d", len(b), len(wire.Manifest), wire.Omitted)
}

func TestWPDManifestNativeReaderHasNoEventValueInputs(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "local_wpd_trace_consumer_windows.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "readWPDManifestTemplates" {
			continue
		}
		found = true
		reads := map[string]int{}
		ast.Inspect(fn, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				switch id.Name {
				case "wpdEventRecord", "wpdEventMetadata", "wpdDecodeCommand", "wpdGetProperty", "wpdGetPropertySize", "wpdEventInformation", "UserData":
					t.Errorf("manifest reader acquired event-value dependency %s", id.Name)
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "read" {
					if len(call.Args) != 3 {
						t.Fatal("unexpected native reader inputs")
					}
					proc, ok := call.Args[0].(*ast.Ident)
					if !ok {
						t.Fatal("dynamic native API")
					}
					reads[proc.Name]++
				}
			}
			return true
		})
		if len(reads) != 2 || reads["wpdManifestEvents"] != 1 || reads["wpdManifestInformation"] != 1 {
			t.Fatal(reads)
		}
	}
	if !found {
		t.Fatal("missing native reader")
	}
}
