package logfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnosticServiceTailSkipsPartialRecords(t *testing.T) {
	dir := t.TempDir()
	complete := evidencePrefix + `{"ipad_connection":{"state":"connecting"}}` + "\n"
	input := strings.Repeat("old", 36000) + "\n" + complete + evidencePrefix + `{"incomplete":`
	if err := os.WriteFile(filepath.Join(dir, "service.log"), []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	tails := ReadDiagnosticTails(dir)
	if tails.Service != complete {
		t.Fatalf("expected only one complete record, got %d bytes", len(tails.Service))
	}
}

func TestDiagnosticBudgetPreservesAllLatestIPadSections(t *testing.T) {
	connection := evidencePrefix + `{"ipad_connection":{"state":"connecting"}}` + "\n"
	network := evidencePrefix + `{"ipad_runtime_network":{"status":"sampled"}}` + "\n"
	trust := evidencePrefix + `{"ipad_trust_timeline":{"run_id":"test"}}` + "\n"
	timing := evidencePrefix + `{"connection_timing":{"mode":"fast","persistence":"saved"}}` + "\n"
	photo := evidencePrefix + `{"photo_isolation":{"phase":"waiting_photo_interface","effective":false}}` + "\n"
	usb := evidencePrefix + `{"local_usb_trace":{"coverage":"not_covered","target_scope":"unknown"}}` + "\n"
	pnp := evidencePrefix + `{"pnp_native_trace":{"coverage":"incomplete","queue_dropped":1}}` + "\n"
	service := strings.Repeat("\x00", 48*1024-len(connection)-len(network)-len(trust)-len(timing)-len(photo)-len(usb)-len(pnp)-1) + "\n" + connection + network + trust + timing + photo + usb + pnp
	payload, err := MarshalDiagnosticSnapshot(map[string]any{"metadata": strings.Repeat("x", 160*1024)}, DiagnosticTails{Service: service})
	if err != nil || len(payload) > diagnosticLimit {
		t.Fatal("unbounded snapshot", err, len(payload))
	}
	var result struct {
		Logs      map[string]string `json:"logs"`
		Truncated map[string]bool   `json:"log_prefixes_omitted_for_transport"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Logs["installer.log"], connection) || !strings.Contains(result.Logs["installer.log"], network) || !strings.Contains(result.Logs["installer.log"], trust) || !strings.Contains(result.Logs["installer.log"], timing) || !strings.Contains(result.Logs["installer.log"], photo) || !result.Truncated["service.log"] {
		t.Fatal("latest independent sections were lost or truncation was hidden")
	}
	if !strings.Contains(result.Logs["installer.log"], usb) || !strings.Contains(result.Logs["installer.log"], pnp) {
		t.Fatal("native coverage or loss diagnostics lost in transport")
	}
	if _, err := MarshalDiagnosticSnapshot(map[string]any{"metadata": strings.Repeat("x", diagnosticLimit)}, DiagnosticTails{}); err == nil {
		t.Fatal("unbounded metadata accepted")
	}
}

func TestRotationRetainsOnlyMissingSameVersionEvidenceAndLabelsOrigin(t *testing.T) {
	previous := evidencePrefix + `{"core_version":"29","wpd_trace":{"events":3}}` + "\n" + evidencePrefix + `{"core_version":"28","photo_policy":{"policy_armed":true}}` + "\n" + evidencePrefix + `{"core_version":"29","ncm_direct":{"phase":"old"}}` + "\n"
	current := evidencePrefix + `{"core_version":"29","ncm_direct":{"phase":"new"}}` + "\n"
	got := rotatedDiagnosticEvidence(previous, current)
	if !strings.Contains(got, `"wpd_trace":{"events":3}`) || !strings.Contains(got, `"evidence_from_rotated_log":true`) || strings.Contains(got, "photo_policy") || strings.Contains(got, "ncm_direct") {
		t.Fatal(got)
	}
	if rotatedDiagnosticEvidence(previous, "ordinary output\n") != "" {
		t.Fatal("unknown current version reused archived state")
	}
}
