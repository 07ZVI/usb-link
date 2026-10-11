package ipadncm

import (
	"encoding/json"
	"math"
	"strings"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"testing"
)

func TestMacBridgeTimingReportRequiresActualBindingAndIndependentCopies(t *testing.T) {
	rows := []netconfig.BridgeNetworkScriptTiming{{Operation: "setup", Count: 1, DurationMS: 12.5, Success: true}}
	m := macconnection.Result{BridgeProcessPID: 7, BridgeProcessCreation: 99, BridgeProcessBound: true, BridgeNetworkScriptTimings: rows}
	var r ApplicationResult
	applyMacBridgeDiagnostics(&r, m)
	rows[0].DurationMS = 0
	if !r.MacBridgeProcessBound || r.MacBridgeProcessPID != 7 || r.MacBridgeProcessCreation != 99 || r.MacBridgeNetworkScriptTimings[0].DurationMS != 12.5 {
		t.Fatal("producer/report alias or binding lost", r)
	}
	b, e := json.Marshal(r)
	if e != nil || !strings.Contains(string(b), `"mac_bridge_process_creation_filetime":"99"`) {
		t.Fatal("creation identity must survive JSON number precision", string(b), e)
	}
	s := applicationState{r: r}
	a := s.snapshot()
	a.MacBridgeNetworkScriptTimings[0].DurationMS = 123
	if s.snapshot().MacBridgeNetworkScriptTimings[0].DurationMS != 12.5 {
		t.Fatal("snapshot aliases retained diagnostics")
	}
	for _, m := range []macconnection.Result{
		{BridgeProcessPID: 7, BridgeProcessCreation: 99, BridgeNetworkScriptTimings: rows},
		{BridgeProcessPID: 7, BridgeProcessBound: true, BridgeNetworkScriptTimings: rows},
		{},
	} {
		applyMacBridgeDiagnostics(&r, m)
		if r.MacBridgeProcessBound || r.MacBridgeProcessPID != 0 || r.MacBridgeProcessCreation != 0 || len(r.MacBridgeNetworkScriptTimings) != 0 {
			t.Fatal("unbound/new attempt retained old sample")
		}
	}
}
func TestMacBridgeTimingSnapshotBoundsAndRejectsUnsafeScalars(t *testing.T) {
	rows := make([]netconfig.BridgeNetworkScriptTiming, 20)
	for i := range rows {
		rows[i] = netconfig.BridgeNetworkScriptTiming{Operation: "setup", Count: 1, DurationMS: 5}
	}
	rows[0].Operation = "private path"
	rows[1].DurationMS = math.NaN()
	rows[2].DurationMS = math.Inf(1)
	rows[3].Count = 2
	rows[4].DurationMS = 120001
	rows[5].DurationMS = -1
	got := netconfig.CopyBridgeNetworkScriptTimings(rows)
	if len(got) != 10 {
		t.Fatal("unbounded/unvalidated snapshot", len(got))
	}
}

func TestMacNullProjectionReportCopiesAndClearsUnbound(t *testing.T) {
	p := &netconfig.MacNullProjection{Schema: 1, ReadOnly: true}
	for i := 0; i < 5; i++ {
		p.Rows = append(p.Rows, netconfig.MacNullProjectionRow{SelectorIndex: i, Status: "unavailable", Phase: "public_rule", PublicProgramKind: "unread", CIMAppPathKind: "unread"})
	}
	var r ApplicationResult
	applyMacBridgeDiagnostics(&r, macconnection.Result{BridgeProcessPID: 1, BridgeProcessCreation: 2, BridgeProcessBound: true, FirewallNullProjection: p})
	p.Rows[0].Status = "observed"
	if r.MacFirewallNullProjection == nil || r.MacFirewallNullProjection.Rows[0].Status != "unavailable" {
		t.Fatal("producer/report alias")
	}
	state := applicationState{r: r}
	snap := state.snapshot()
	snap.MacFirewallNullProjection.Rows[0].Status = "observed"
	if state.snapshot().MacFirewallNullProjection.Rows[0].Status != "unavailable" {
		t.Fatal("snapshot alias")
	}
	applyMacBridgeDiagnostics(&r, macconnection.Result{FirewallNullProjection: p})
	if r.MacFirewallNullProjection != nil {
		t.Fatal("unbound sample retained")
	}
}

func TestMacAnchorProjectionReportCopiesAndClearsUnbound(t *testing.T) {
	p := &netconfig.MacAnchorProjection{Schema: 1, ReadOnly: true}
	for i := 0; i < 5; i++ {
		p.Rows = append(p.Rows, netconfig.MacAnchorProjectionRow{SelectorIndex: i, Status: "unavailable", Fields: []netconfig.MacAnchorProjectionField{}})
	}
	var r ApplicationResult
	applyMacBridgeDiagnostics(&r, macconnection.Result{BridgeProcessPID: 1, BridgeProcessCreation: 2, BridgeProcessBound: true, FirewallAnchorProjection: p})
	p.ReadOnly = false
	if r.MacFirewallAnchorProjection == nil || !r.MacFirewallAnchorProjection.ReadOnly {
		t.Fatal("producer/report alias")
	}
	state := applicationState{r: r}
	snap := state.snapshot()
	snap.MacFirewallAnchorProjection.ReadOnly = false
	if !state.snapshot().MacFirewallAnchorProjection.ReadOnly {
		t.Fatal("snapshot alias")
	}
	applyMacBridgeDiagnostics(&r, macconnection.Result{FirewallAnchorProjection: p})
	if r.MacFirewallAnchorProjection != nil {
		t.Fatal("unbound retained")
	}
}
