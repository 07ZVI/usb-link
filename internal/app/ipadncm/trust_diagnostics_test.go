package ipadncm

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"suhang/usbnet/internal/buildinfo"
)

func TestTrustTimelineIndependentBaselineChangesAndFreshness(t *testing.T) {
	m := &trustDiagnosticState{}
	start := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if !m.start(start, "random-session") || m.start(start.Add(time.Second), "another") {
		t.Fatal("observer epoch not idempotent")
	}
	m.subscription(start, 0, "PRIVATE_ERROR")
	m.pnp(start, 0, trustPNPState{Read: "ok"})
	m.amds(start, 0, trustServiceState{Read: "ok", State: 4, PID: 50})
	baseline := m.snapshot()
	if len(baseline.Events) != 4 || baseline.NotificationStatus != "unavailable_polling_continues" {
		t.Fatal(baseline)
	}
	m.pnp(start.Add(time.Second), 1, trustPNPState{Read: "ok"})
	m.amds(start.Add(time.Second), 1, trustServiceState{Read: "ok", State: 4, PID: 50})
	unchanged := m.snapshot()
	if len(unchanged.Events) != 4 || unchanged.LastPNPSampleMS != 1000 || unchanged.LastAMDSSampleMS != 1000 || unchanged.LastPNPSampleUTC == baseline.LastPNPSampleUTC {
		t.Fatal("stable observations lost freshness or flooded events", unchanged)
	}
	m.pnp(start.Add(2*time.Second), 1, trustPNPState{Read: "access_denied"})
	m.amds(start.Add(2*time.Second), 1, trustServiceState{Read: "query_failed"})
	m.pnp(start.Add(3*time.Second), 1, trustPNPState{Read: "access_denied"})
	m.amds(start.Add(3*time.Second), 1, trustServiceState{Read: "query_failed"})
	failed := m.snapshot()
	if failed.PNPFailures != 2 || failed.ServiceFailures != 2 || len(failed.Events) != 6 || failed.LastAMDSSampleMS != 3000 {
		t.Fatal("repeated failure hidden or repeated events", failed)
	}
	m.pnp(start.Add(4*time.Second), 1, trustPNPState{Read: "ok", Roots: 1, Controls: 2, Nodes: []trustNodeState{{Role: "R", Service: "C", Readable: true, Started: true}, {Role: "02", Service: "N", Readable: true, Started: true}}})
	m.amds(start.Add(4*time.Second), 1, trustServiceState{Read: "ok", State: 4, PID: 51})
	got := m.snapshot()
	if !got.Active || got.PNP.Read != "ok" || got.AMDS.PID != 51 || len(got.Events) != 8 {
		t.Fatal("observer did not recover", got)
	}
	if got.IPadPromptObserved || got.PairingRequestObserved {
		t.Fatal("state changes became prompt proof")
	}
	m.stop(start.Add(5*time.Second), 2)
	m.pnp(start.Add(6*time.Second), 2, trustPNPState{Read: "ok"})
	if m.snapshot().Active || m.snapshot().LastPNPSampleMS != 4000 {
		t.Fatal("stopped observer accepted new samples")
	}
}

func TestTrustTimelineMarkersAndOperationsAreGatedAndBounded(t *testing.T) {
	old, oldFlag := trustDiagnostics, buildinfo.LocalDiagnostics
	t.Cleanup(func() { trustDiagnostics = old; buildinfo.LocalDiagnostics = oldFlag })
	trustDiagnostics = &trustDiagnosticState{}
	trustDiagnostics.start(time.Now(), "new-run")
	buildinfo.LocalDiagnostics = "false"
	RecordTrustPromptMarker(1)
	RecordTrustOperation(1, "usb_mode_switch_begin")
	if len(TrustDiagnosticsSnapshot().Events) != 1 {
		t.Fatal("public build recorded diagnostics")
	}
	buildinfo.LocalDiagnostics = "true"
	RecordTrustPromptMarker(0)
	RecordTrustPromptMarker(3)
	RecordTrustOperation(1, "PRIVATE_STAGE")
	if len(TrustDiagnosticsSnapshot().Events) != 1 {
		t.Fatal("unknown marker or operation accepted")
	}
	RecordTrustPromptMarker(1)
	RecordTrustPromptMarker(2)
	RecordTrustOperation(9, "usb_mode_switch_begin")
	s := TrustDiagnosticsSnapshot()
	if len(s.Events) != 4 || s.Events[1].Source != "user_marker" || s.Events[2].Kind != "prompt_2_recorded" || s.Events[3].Attempt != 9 {
		t.Fatal(s)
	}
	for i := 0; i < 40; i++ {
		RecordTrustOperation(9, "native_start_check_end")
	}
	s = TrustDiagnosticsSnapshot()
	if len(s.Events) != trustEventLimit || s.Dropped != 24 {
		t.Fatal("event ring not bounded", s.Dropped, len(s.Events))
	}
	s.Events[0].Data = "PRIVATE_MUTATION"
	if TrustDiagnosticsSnapshot().Events[0].Data != "" {
		t.Fatal("event cache aliased")
	}
}

func TestTrustTimelinePrivacyAndPayloadBound(t *testing.T) {
	m := &trustDiagnosticState{}
	start := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	m.start(start, strings.Repeat("a", 24))
	nodes := make([]trustNodeState, 8)
	for i := range nodes {
		nodes[i] = trustNodeState{Role: "PRIVATE_ROOT", Service: "PRIVATE_SERVICE", Problem: ^uint32(0)}
	}
	for i := 0; i < 30; i++ {
		m.pnp(start.Add(time.Duration(i)*time.Second), ^uint64(0), trustPNPState{Read: "ok", Roots: 4096, Controls: i, Nodes: nodes})
	}
	m.amds(start.Add(30*time.Second), ^uint64(0), trustServiceState{Read: "ok", State: 4, PID: ^uint32(0)})
	s := m.snapshot()
	if len(s.PNP.Nodes) != trustNodeLimit || s.PNP.Omitted != 4 {
		t.Fatal("node budget missing", s.PNP)
	}
	s.PNP.Nodes[0].Service = "PRIVATE_MUTATION"
	if m.snapshot().PNP.Nodes[0].Service != "U" {
		t.Fatal("node cache aliased")
	}
	body, err := json.Marshal(map[string]any{"core_version": "0.10.18", "ipad_trust_timeline": m.snapshot(), "apple_service_trial": LocalTrustServiceTrial{
		Requested: true, Running: true, Phase: "awaiting_service_restore", Error: strings.Repeat("E", 80), RestoreError: strings.Repeat("R", 80),
		Before: ^uint32(0), During: ^uint32(0), After: ^uint32(0), StartType: ^uint32(0), AttemptBefore: ^uint64(0), AttemptAfter: ^uint64(0),
	}})
	if err != nil || len(body) > 7900 || strings.Contains(string(body), "PRIVATE") {
		t.Fatalf("bytes=%d err=%v private=%v", len(body), err, strings.Contains(string(body), "PRIVATE"))
	}
	t.Logf("bounded timeline bytes=%d", len(body))
	m.pnp(start.Add(31*time.Second), 1, trustPNPState{Read: "PRIVATE_NATIVE_ERROR", Roots: 1, Nodes: nodes})
	m.amds(start.Add(31*time.Second), 1, trustServiceState{Read: "PRIVATE_SERVICE_ERROR", State: 4, PID: 22})
	body, _ = json.Marshal(m.snapshot())
	if strings.Contains(string(body), "PRIVATE") || m.snapshot().PNP.Read != "query_failed" || m.snapshot().AMDS.PID != 0 {
		t.Fatal("failed query leaked native text or stale state")
	}
}

func TestTrustPNPPhotoTransportAndActiveNCMShareBoundedBudget(t *testing.T) {
	nodes := []trustNodeState{
		{Role: "R", Service: "C"},
		{Role: "00", Service: "P", Readable: true, Problem: 22},
		{Role: "01", Service: "W", Readable: true, Started: true},
		{Role: "02", Service: "N", Readable: true, Problem: 10},
		{Role: "04", Service: "N", Readable: true, Started: true},
		{Role: "03", Service: "X"},
		{Role: "05", Service: "F"},
		{Role: "R", Service: "C"},
	}
	p := normalizeTrustPNP(trustPNPState{Read: "ok", Roots: 2, Controls: 2, Nodes: nodes, Omitted: 3})
	if len(p.Nodes) != 4 || p.Omitted != 7 || p.Roots != 2 || p.Controls != 2 {
		t.Fatal("selection concealed omitted nodes or changed counts", p)
	}
	for i, role := range []string{"R", "00", "01", "04"} {
		if p.Nodes[i].Role != role {
			t.Fatalf("slot %d: got %+v, want %s", i, p.Nodes[i], role)
		}
	}
	if p.Nodes[1].Service != "P" || p.Nodes[1].Problem != 22 || p.Nodes[2].Service != "W" {
		t.Fatal("photo disable or Apple transport state lost", p.Nodes)
	}
	nodes[4].Started = false
	nodes[4].Problem = 10
	p = normalizeTrustPNP(trustPNPState{Read: "ok", Nodes: nodes})
	if p.Nodes[3].Role != "02" || p.Nodes[3].Problem != 10 {
		t.Fatal("failed NCM hidden when no active NCM exists", p.Nodes)
	}
	p = normalizeTrustPNP(trustPNPState{Read: "ok", Nodes: []trustNodeState{{Role: "00", Service: "P"}, {Role: "01", Service: "F"}}})
	if p.Nodes[0].Service != "P" || p.Nodes[1].Service != "F" {
		t.Fatal("WPD and generic UMDF services collapsed", p.Nodes)
	}
}

func TestTrustWindowsObserverHasReadOnlyNativeBoundary(t *testing.T) {
	b, err := os.ReadFile("trust_diagnostics_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, bad := range []string{"mgr.Connect(", "SERVICE_ALL_ACCESS", "SC_MANAGER_ALL_ACCESS", "SERVICE_START", "SERVICE_STOP", "SERVICE_CHANGE_CONFIG", "ControlService(", "StartService(", "Pair(", "queryModel(", "inventory(", "RunNetworkOnlyAppleControl(", "readAMDSDiagnosticReceipt("} {
		if strings.Contains(s, bad) {
			t.Fatal("observer gained device/control authority", bad)
		}
	}
	for _, need := range []string{"windows.SC_MANAGER_CONNECT", "windows.SERVICE_QUERY_STATUS", "windows.QueryServiceStatusEx(", "inventoryPnP(ctx)", "deviceguard.SubscribeFilteredChanges(", "time.NewTicker(time.Second)", "ctx.Done()"} {
		if !strings.Contains(s, need) {
			t.Fatal("observer contract missing", need)
		}
	}
}
