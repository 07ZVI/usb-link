//go:build usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func wpdMTPFixtures(t *testing.T) map[uint16][]wpdManifestField {
	t.Helper()
	var raw []struct {
		ID     uint16 `json:"event_id"`
		Fields [][6]json.RawMessage
	}
	if e := json.Unmarshal([]byte(wpdMTPManifest35), &raw); e != nil {
		t.Fatal(e)
	}
	out := map[uint16][]wpdManifestField{}
	for _, v := range raw {
		for _, tuple := range v.Fields {
			var f wpdManifestField
			dest := []any{&f.Name, &f.InType, &f.OutType, &f.Flags, &f.Count, &f.Length}
			for i, d := range dest {
				if e := json.Unmarshal(tuple[i], d); e != nil {
					t.Fatal(e)
				}
			}
			out[v.ID] = append(out[v.ID], f)
		}
	}
	return out
}
func wpdMTPMetadata(id uint16, f []wpdManifestField) []byte {
	b := manifestFixture(f)
	binary.LittleEndian.PutUint16(b[32:], id)
	return b
}
func TestWPDExactMTPMatchesActual35Definitions(t *testing.T) {
	for id, fields := range wpdMTPFixtures(t) {
		b := wpdMTPMetadata(id, fields)
		got := wpdExactMTPCommandField("mtp", id, 0, b)
		if len(got) != 1 || got[0] != (wpdTraceNumericField{"MTP_Opcode", 2}) {
			t.Fatal(id, got)
		}
		for row := range fields {
			for col := 0; col < 6; col++ {
				t.Run(fmt.Sprintf("%d_field%d_col%d", id, row, col), func(t *testing.T) {
					changed := append([]wpdManifestField(nil), fields...)
					f := &changed[row]
					switch col {
					case 0:
						f.Name += "X"
					case 1:
						f.InType++
					case 2:
						f.OutType++
					case 3:
						f.Flags ^= 16
					case 4:
						f.Count++
					case 5:
						f.Length++
					}
					if len(wpdExactMTPCommandField("mtp", id, 0, wpdMTPMetadata(id, changed))) != 0 {
						t.Fatal("changed definition admitted")
					}
				})
			}
		}
		for _, provider := range []string{"api", "usb", "", "unknown"} {
			if len(wpdExactMTPCommandField(provider, id, 0, b)) != 0 {
				t.Fatal(provider)
			}
		}
		if len(wpdExactMTPCommandField("mtp", id, 1, b)) != 0 || len(wpdExactMTPCommandField("mtp", 2004, 0, b)) != 0 {
			t.Fatal("wrong event admitted")
		}
		b[34] = 1
		if len(wpdExactMTPCommandField("mtp", id, 0, b)) != 0 {
			t.Fatal("metadata version mismatch")
		}
		b[34] = 0
		binary.LittleEndian.PutUint16(b[32:], 2004)
		if len(wpdExactMTPCommandField("mtp", id, 0, b)) != 0 {
			t.Fatal("metadata event mismatch")
		}
		b = wpdMTPMetadata(id, fields)
		binary.LittleEndian.PutUint32(b[48:], 1)
		if len(wpdExactMTPCommandField("mtp", id, 0, b)) != 0 {
			t.Fatal("nonmanifest admitted")
		}
	}
}
func TestWPDExactMTPReadsOnlyOpcodeScalar(t *testing.T) {
	for id, fields := range wpdMTPFixtures(t) {
		candidates := wpdExactMTPCommandField("mtp", id, 0, wpdMTPMetadata(id, fields))
		if old, _, _ := wpdTraceInspectMetadata(wpdMTPMetadata(id, fields)); len(old) != 0 {
			t.Fatal("global allowlist expanded", old)
		}
		for _, scenario := range []string{"success", "read_failed", "size_failed", "size_mismatch"} {
			reads, sizes := 0, 0
			field, value, stage, code := wpdTraceDecodeFields(candidates, func(name string) (uint32, uint32) {
				sizes++
				if name != "MTP_Opcode" {
					t.Fatal(name)
				}
				if scenario == "size_failed" {
					return 0, 5
				}
				if scenario == "size_mismatch" {
					return 4, 0
				}
				return 2, 0
			}, func(name string, n uint32) (uint64, uint32) {
				reads++
				if name != "MTP_Opcode" || n != 2 {
					t.Fatal(name, n)
				}
				if scenario == "read_failed" {
					return 0, 5
				}
				return 0x1001, 0
			})
			if sizes != 1 {
				t.Fatal(sizes)
			}
			if scenario == "success" {
				if stage != "decoded" || field != "MTP_Opcode" || value != 0x1001 || code != 0 || reads != 1 {
					t.Fatal(field, value, stage, code, reads)
				}
			} else if field != "" || value != 0 || stage != scenario || reads > 1 {
				t.Fatal(field, value, stage, code, reads)
			}
			if strings.HasPrefix(scenario, "size_") && reads != 0 {
				t.Fatal("read after size rejection")
			}
		}
	}
}

func TestWPDStrictResponseReadsThreeBoundedScalarsIndependently(t *testing.T) {
	f := wpdMTPFixtures(t)[2001]
	candidates := wpdExactMTPCommandField("mtp", 2001, 0, wpdMTPMetadata(2001, f))
	for _, scenario := range []string{"zero_hr_success", "opcode_failure", "code_failure", "transport_failure", "code_size_mismatch", "not_strict_response"} {
		t.Run(scenario, func(t *testing.T) {
			queries, reads := map[string]int{}, map[string]int{}
			widths := map[string]uint32{"MTP_Opcode": 2, "MTP_Response_Code": 2, "MTP_Response_Retrieval_HR_From_Transport": 4}
			field, value, stage, native, response := wpdDecodeCommandValues(candidates, scenario != "not_strict_response", func(name string) (uint32, uint32) {
				width, ok := widths[name]
				if !ok {
					t.Fatal("unexpected value query", name)
				}
				queries[name]++
				if scenario == "code_size_mismatch" && name == "MTP_Response_Code" {
					return 4, 0
				}
				return width, 0
			}, func(name string, size uint32) (uint64, uint32) {
				if widths[name] != size {
					t.Fatal(name, size)
				}
				reads[name]++
				if scenario == "opcode_failure" && name == "MTP_Opcode" || scenario == "code_failure" && name == "MTP_Response_Code" || scenario == "transport_failure" && name == "MTP_Response_Retrieval_HR_From_Transport" {
					return 0, 5
				}
				if name == "MTP_Opcode" {
					return 0x1002, 0
				}
				if name == "MTP_Response_Code" {
					return 0x2001, 0
				}
				return 0, 0
			})
			if scenario == "opcode_failure" {
				if field != "" || stage != "read_failed" || native != 5 || response != (wpdMTPResponse{}) || len(queries) != 1 || len(reads) != 1 {
					t.Fatal(field, stage, native, response, queries, reads)
				}
				return
			}
			if field != "MTP_Opcode" || value != 0x1002 || stage != "decoded" || native != 0 {
				t.Fatal(field, value, stage, native)
			}
			if scenario == "not_strict_response" {
				if response != (wpdMTPResponse{}) || len(queries) != 1 {
					t.Fatal(response, queries)
				}
				return
			}
			if len(queries) != 3 {
				t.Fatal(queries)
			}
			if scenario == "code_failure" {
				if response.CodeRead || response.CodeError != "read_failed" || response.CodeNative != 5 || !response.TransportRead {
					t.Fatal(response)
				}
			} else if scenario == "code_size_mismatch" {
				if response.CodeRead || response.CodeError != "size_mismatch" || reads["MTP_Response_Code"] != 0 || !response.TransportRead {
					t.Fatal(response)
				}
			} else if !response.CodeRead || response.Code != 0x2001 {
				t.Fatal(response)
			}
			if scenario == "transport_failure" {
				if response.TransportRead || response.TransportError != "read_failed" || response.TransportNative != 5 || !response.CodeRead {
					t.Fatal(response)
				}
			} else if !response.TransportRead || response.TransportHR != 0 {
				t.Fatal("zero HRESULT must be read success", response)
			}
			b, _ := json.Marshal(response)
			if !strings.Contains(string(b), `"transport_hr":0`) {
				t.Fatal(string(b))
			}
		})
	}
	zero, _ := json.Marshal(wpdMTPResponse{})
	if !strings.Contains(string(zero), `"transport_read":false`) || !strings.Contains(string(zero), `"transport_hr":0`) {
		t.Fatal(string(zero))
	}
}

func TestWPDFirstDecodedRetainsFirstAndLastAcrossModeInterval(t *testing.T) {
	var s localWPDTraceSample
	first := localWPDTraceEvent{Provider: "mtp", EventID: 2001, CommandCode: 0x1002, CommandField: "MTP_Opcode", CommandRole: "response_corresponding_command", OpcodeDecoded: true, MS: 100, EventUTC: "2026-10-17T12:00:00Z", PID: 12, Response: wpdMTPResponse{CodeRead: true, Code: 0x2001, TransportRead: true}}
	s.retainDecoded(first)
	before := s.FirstDecoded
	last := first
	last.MS = 3100
	last.EventUTC = "2026-10-17T12:00:03Z"
	last.PID = 34
	last.Response = wpdMTPResponse{CodeError: "read_failed", CodeNative: 5, TransportRead: true, TransportHR: 0x80070005}
	s.retainDecoded(last)
	got := s.FirstDecoded[0]
	if got.MS != first.MS || got.EventUTC != first.EventUTC || got.PID != first.PID || got.Response != first.Response || got.Observations != 2 || got.ObservationUnit != "etw_events" || got.LastReceivedMS != last.MS || got.LastEventUTC != last.EventUTC || got.LastResponse != last.Response {
		t.Fatal(got)
	}
	if before[0].Observations != 1 || before[0].LastResponse != first.Response {
		t.Fatal("snapshot changed")
	}
	s.FirstDecoded[0].Observations = ^uint64(0)
	s.retainDecoded(last)
	if s.FirstDecoded[0].Observations != ^uint64(0) {
		t.Fatal("count wrapped")
	}
}
func TestWPDFirstDecodedSurvivesPeriodicEventsAndDuplicates(t *testing.T) {
	var s localWPDTraceSample
	first := localWPDTraceEvent{Provider: "mtp", EventID: 2000, Version: 0, CommandField: "MTP_Opcode", CommandCode: 0x1001, OpcodeDecoded: true, MS: 10}
	first.CommandRole = wpdDecodedCommandRole(first)
	s.retainDecoded(first)
	wantFirst := s.FirstDecoded[0]
	for i := 0; i < 100; i++ {
		s.retainDecoded(localWPDTraceEvent{Provider: "mtp", EventID: 2004, MS: int64(i)})
		repeat := first
		repeat.MS = int64(i + 100)
		s.retainDecoded(repeat)
	}
	response := first
	response.EventID = 2001
	response.CommandRole = wpdDecodedCommandRole(response)
	s.retainDecoded(response)
	wantFirst.Observations = 101
	wantFirst.LastReceivedMS = 199
	if s.FirstDecoded[0] != wantFirst || s.FirstDecoded[1].CommandRole != "response_corresponding_command" || s.FirstDecoded[0].CommandRole != "command_context" {
		t.Fatal(s.FirstDecoded)
	}
	for i := 0; i < 6; i++ {
		v := first
		v.CommandCode = uint64(0x1010 + i)
		s.retainDecoded(v)
	}
	before := s.FirstDecoded
	overflow := first
	overflow.CommandCode = 0x9999
	s.retainDecoded(overflow)
	if s.FirstDecoded != before || s.DecodedUnretainedEvents != 1 {
		t.Fatal(s)
	}
	copy := s
	copy.FirstDecoded[0].MS = 123
	if s.FirstDecoded != before {
		t.Fatal("snapshot alias")
	}
}
func TestWPDFirstDecodedBudgetKeepsFirstAndSwitches(t *testing.T) {
	s := newLocalWPDTraceController().snapshot()
	s.CaptureDenied = ^uint64(0)
	s.CriticalArchive = wpdCriticalArchiveCounts{Seen: ^uint64(0), Enqueued: ^uint64(0), Rejected: ^uint64(0), RejectedExtended: ^uint64(0), RejectedLength: ^uint64(0), Overflow: ^uint64(0), Decoded: ^uint64(0), Failed: ^uint64(0), ResponseFailures: ^uint64(0), ArchiveEnqueued: ^uint64(0), ArchiveNotQueued: ^uint64(0), Pending: 128, InFlight: 1, HighWater: 128, Closed: true}
	s.SummaryArchive = s.CriticalArchive
	s.CriticalSampling = wpdCriticalSampling{{Seen: ^uint64(0), Parsed: ^uint64(0)}, {Seen: ^uint64(0), Skipped: ^uint64(0)}}
	s.Requested, s.SavedEnabled = true, true
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
	s.DecodedUnretainedEvents, s.HeaderOnlyEvents, s.SchemaUnretainedEvents = ^uint64(0), ^uint64(0), ^uint64(0)
	s.DecodeCounts = localWPDTraceDecodeCounts{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	for i := range s.Providers {
		s.Providers[i] = localWPDTraceProvider{Label: "api", Kind: "unknown", OtherLoggerCount: ^uint32(0), Enabled: true, EnabledUTC: s.SampledUTC, SkipCode: "invalid_enable_value", NativeCode: ^uint32(0), Registration: "registered_with_pre_enable", InstanceCount: 1024, FlagsOR: ^uint32(0), Schema: "tracelogging", ModernInstances: 1024, LegacyInstances: 1024, PreEnabledInstances: 1024, UnknownInstances: 1024}
	}
	for i := range s.FirstDecoded {
		s.FirstDecoded[i] = localWPDTraceEvent{Provider: "mtp", EventID: 2001, Version: 255, PID: ^uint32(0), Task: 65535, ETWOpcode: 255, MS: 9223372036854775807, EventUTC: s.SampledUTC, OpcodeDecoded: true, CommandField: "OperationCode", CommandCode: ^uint64(0) - uint64(i), CommandRole: "response_corresponding_command"}
		s.FirstDecoded[i].Observations = ^uint64(0)
		s.FirstDecoded[i].ObservationUnit = "etw_events"
		s.FirstDecoded[i].LastReceivedMS = 9223372036854775807
		s.FirstDecoded[i].LastEventUTC = s.SampledUTC
		s.FirstDecoded[i].Response = wpdMTPResponse{Code: 65535, CodeError: "size_mismatch", CodeNative: ^uint32(0), TransportHR: ^uint32(0), TransportError: "size_mismatch", TransportNative: ^uint32(0)}
		s.FirstDecoded[i].LastResponse = s.FirstDecoded[i].Response
		s.Schemas[i] = localWPDTraceSchema{Provider: "mtp", Stage: "no_candidate"}
		s.Recent = append(s.Recent, s.FirstDecoded[i])
	}
	for i := range s.ManifestTemplates {
		s.ManifestTemplates[i] = wpdManifestTemplate{Provider: "mtp", Source: wpdManifestSource, Stage: "complete", Complete: true, Properties: 16, Top: 16}
		for j := range s.ManifestTemplates[i].Fields {
			s.ManifestTemplates[i].Fields[j] = wpdManifestField{Name: strings.Repeat("x", 48)}
		}
	}
	withQuery := s
	withQuery.Ownership = &wpdSessionQueryEvidence{Schema: 2, Mode: ^uint32(0), MaxFileMiB: ^uint32(0), NameOffset: ^uint32(0), FileOffset: ^uint32(0), BufferSize: 4216, Mismatch: 31}
	queryBytes, queryErr := json.Marshal(withQuery)
	var queryWire struct {
		Ownership *wpdSessionQueryEvidence `json:"query_ownership"`
		First     []localWPDTraceEvent     `json:"first_decoded"`
		Omitted   int                      `json:"decoded_omitted"`
	}
	if queryErr != nil || len(queryBytes) > 4096 || json.Unmarshal(queryBytes, &queryWire) != nil || queryWire.Ownership == nil || queryWire.Ownership.Mismatch != 31 || len(queryWire.First)+queryWire.Omitted != 8 {
		t.Fatal("query failure budget or explicit omission", len(queryBytes), queryErr)
	}
	before := s.FirstDecoded
	b, e := json.Marshal(s)
	if e != nil || len(b) > 4096 {
		t.Fatal(len(b), e)
	}
	var wire struct {
		ProviderDetailsOmitted uint8                    `json:"provider_details_omitted"`
		Providers              [3]localWPDTraceProvider `json:"providers"`
		Requested              bool
		Saved                  bool                     `json:"saved_enabled"`
		First                  []localWPDTraceEvent     `json:"first_decoded"`
		Omitted                int                      `json:"decoded_omitted"`
		ManifestOmitted        int                      `json:"manifest_omitted"`
		SchemasOmitted         int                      `json:"schemas_omitted"`
		RecentOmitted          int                      `json:"recent_omitted"`
		CriticalArchive        wpdCriticalArchiveCounts `json:"critical_archive"`
		SummaryArchive         wpdCriticalArchiveCounts `json:"summary_archive"`
		Sampling               struct {
			Command  wpdCriticalEventCounts `json:"mtp2000_v0"`
			Response wpdCriticalEventCounts `json:"mtp2001_v0"`
		} `json:"critical_sampling"`
	}
	if json.Unmarshal(b, &wire) != nil || !wire.Requested || !wire.Saved || len(wire.First) == 0 || wire.First[0] != before[0] || len(wire.First)+wire.Omitted != 8 || wire.Omitted == 0 || wire.ManifestOmitted != 4 || wire.SchemasOmitted != 8 || wire.RecentOmitted != 8 || s.FirstDecoded != before || s.DecodedOmitted != 0 {
		t.Fatal(string(b))
	}
	if wire.ProviderDetailsOmitted != 3 || wire.Providers[0].Registration != s.Providers[0].Registration {
		t.Fatal("provider truncation not explicit", string(b))
	}
	if wire.CriticalArchive != s.CriticalArchive || wire.SummaryArchive != s.SummaryArchive {
		t.Fatal("budget dropped asynchronous queue counters", string(b))
	}
	if wire.Sampling.Command != s.CriticalSampling[0] || wire.Sampling.Response != s.CriticalSampling[1] {
		t.Fatal("budget dropped critical sampling counters", string(b))
	}
	t.Logf("first-decoded budget %d bytes, retained %d omitted %d", len(b), len(wire.First), wire.Omitted)
}

// Only static definitions copied from the actual 0.10.35 installed manifest.
const wpdMTPManifest35 = `[{"event_id":2001,"fields":[["SessionID",8,8,0,1,4],["TransactionID",8,8,0,1,4],["MTP_Opcode",6,6,0,1,2],["MTP_Command_Param_count",8,8,0,1,4],["MTP_Command_Params",8,8,4,3,4],["MTP_Response_Retrieval_HR_From_Transport",8,8,0,1,4],["MTP_Response_Code",6,6,0,1,2],["MTP_Response_Param_count",8,8,0,1,4],["MTP_Response_Params",8,8,4,7,4],["MTP_Data_Length",8,8,0,1,4],["MTP_Data_Buffer",14,15,2,1,9]]},{"event_id":2000,"fields":[["SessionID",8,8,0,1,4],["TransactionID",8,8,0,1,4],["MTP_Opcode",6,6,0,1,2],["MTP_Command_Param_count",8,8,0,1,4],["MTP_Command_Params",8,8,4,3,4]]}]`
