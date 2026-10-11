package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCommittedSingleRunningControlRequiresCompleteProof(t *testing.T) {
	base := configuredStartupEvidence{true, true, true, true, true, true, true, true, 1, true}
	if !base.ready() {
		t.Fatal("fully proven single running control rejected")
	}
	checks := []struct {
		name       string
		invalidate func(*configuredStartupEvidence)
	}{
		{"missing durable backup", func(e *configuredStartupEvidence) { e.ReceiptValid = false }},
		{"foreign registry change", func(e *configuredStartupEvidence) { e.RegistryOwned = false }},
		{"replacement iPad", func(e *configuredStartupEvidence) { e.SameUSBRoot = false }},
		{"root problem", func(e *configuredStartupEvidence) { e.RootHealthy = false }},
		{"unreadable second control", func(e *configuredStartupEvidence) { e.NodesReadable = false }},
		{"pending restart", func(e *configuredStartupEvidence) { e.NoRestart = false }},
		{"orphan data or incomplete layout", func(e *configuredStartupEvidence) { e.ControlTopology = false }},
		{"control on another root", func(e *configuredStartupEvidence) { e.AllControlsSameRoot = false }},
		{"problem-zero but not started", func(e *configuredStartupEvidence) { e.StartedControls = 0 }},
		{"impossible started count", func(e *configuredStartupEvidence) { e.StartedControls = 3 }},
		{"ambiguous/disconnected/unmapped NIC", func(e *configuredStartupEvidence) { e.MappingVerified = false }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.invalidate(&e)
			if e.ready() {
				t.Fatal("incomplete proof accepted")
			}
		})
	}
	// The same control count must not weaken the ordinary/ungrouped predicate.
	if (startupReadiness{Controls: 2, StartedControls: 1}).settled() {
		t.Fatal("generic readiness was weakened")
	}
}
func TestStartupDiagnosticHistoryKeepsBoundedImmutableEvidence(t *testing.T) {
	var h startupDiagnosticHistory
	for check := 0; check < 3; check++ {
		d := StartupReadinessDiagnostic{CheckKind: string(rune('A' + check))}
		for sample := 0; sample < 30; sample++ {
			d.add(StartupDiagnosticSample{ElapsedMS: int64(sample), Nodes: []StartupDiagnosticNode{{NodePrefix: "USB\\VID_05AC&PID_12AB&MI_02", DevNodeStatus: "0x8"}}})
		}
		h.record(d)
	}
	s := h.snapshot()
	if len(s) != 2 || s[0].CheckKind != "B" || s[1].CheckKind != "C" || s[1].SampleCount != 30 || len(s[1].Samples) != 12 || s[1].SamplesOmitted != 18 {
		t.Fatal("history/sample budget not maintained", s)
	}
	if s[1].Samples[0].ElapsedMS != 0 || s[1].Samples[2].ElapsedMS != 2 || s[1].Samples[3].ElapsedMS != 21 || s[1].Samples[11].ElapsedMS != 29 {
		t.Fatal("initial and latest samples not preserved")
	}
	s[1].Samples[0].Nodes[0].DevNodeStatus = "mutated"
	if h.snapshot()[1].Samples[0].Nodes[0].DevNodeStatus != "0x8" {
		t.Fatal("caller can mutate retained evidence")
	}
	b, err := json.Marshal(h.snapshot())
	if err != nil || strings.Contains(string(b), "instanceID") || strings.Contains(string(b), "devInst") {
		t.Fatal("private USB identity/handles escaped diagnostics")
	}
}

func TestCommittedTopologyUsesRawCMStartedAndRestartBits(t *testing.T) {
	base := []configuredStartupCMNode{
		{Prefix: `USB\VID_05AC&PID_12AB`, Service: "usbccgp", Status: "0x0180600a", EnumeratorClass: "020000", Root: true},
		{Prefix: `USB\VID_05AC&PID_12AB&MI_02`, Service: "UsbNcm", Status: "0x0180600a", ScopeProven: true},
		{Prefix: `USB\VID_05AC&PID_12AB&MI_04`, Service: "UsbNcm", Problem: 10, Status: "0x01802400", ScopeProven: true},
	}
	good := configuredStartupCMProof(base)
	if !good.RootHealthy || !good.NodesReadable || !good.NoRestart || !good.ControlTopology || !good.AllControlsSameRoot || good.StartedControls != 1 {
		t.Fatal("known committed CM topology not recognized", good)
	}
	for _, tc := range []struct {
		name     string
		change   func([]configuredStartupCMNode) []configuredStartupCMNode
		rejected func(configuredStartupEvidence) bool
	}{
		{"problem zero without DN_STARTED", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[1].Status = "0x01802000"; return n }, func(e configuredStartupEvidence) bool { return e.StartedControls == 0 }},
		{"CM query failure on inactive control", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[2].StateError = "WIN32_1168"; return n }, func(e configuredStartupEvidence) bool { return !e.NodesReadable }},
		{"unparseable inactive control status", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[2].Status = "unavailable"; return n }, func(e configuredStartupEvidence) bool { return !e.NodesReadable }},
		{"inactive control needs restart", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[2].Status = "0x01802500"; return n }, func(e configuredStartupEvidence) bool { return !e.NoRestart }},
		{"root not started", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[0].Status = "0x01802000"; return n }, func(e configuredStartupEvidence) bool { return !e.RootHealthy }},
		{"same PID on another root", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[2].ScopeProven = false; return n }, func(e configuredStartupEvidence) bool { return !e.AllControlsSameRoot }},
		{"old orphan data interface", func(n []configuredStartupCMNode) []configuredStartupCMNode {
			return append(n, configuredStartupCMNode{Prefix: `USB\VID_05AC&PID_12AB&MI_03`, Status: "0x01802400", Problem: 28, ScopeProven: true})
		}, func(e configuredStartupEvidence) bool { return !e.ControlTopology }},
		{"only one control present", func(n []configuredStartupCMNode) []configuredStartupCMNode { return n[:2] }, func(e configuredStartupEvidence) bool { return !e.ControlTopology }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := append([]configuredStartupCMNode(nil), base...)
			e := configuredStartupCMProof(tc.change(nodes))
			if !tc.rejected(e) {
				t.Fatal("unsafe topology was not rejected", e)
			}
		})
	}
}
func TestStartupMappingCannotHideAnUnreadableOrSecondOperationalNIC(t *testing.T) {
	up := startupAdapterObservation{Matched: true, StatisticsRead: true, OperStatus: 1, MediaState: 1}
	down := startupAdapterObservation{Matched: true, StatisticsRead: true, OperStatus: 2, MediaState: 2}
	if !uniqueOperationalStartupMapping([]startupAdapterObservation{up}) || !uniqueOperationalStartupMapping([]startupAdapterObservation{up, down}) {
		t.Fatal("unique operational exact mapping rejected")
	}
	for _, bad := range [][]startupAdapterObservation{
		nil, {down}, {up, up}, {up, {Matched: true, StatisticsRead: true, Error: "NCM_MAPPING_ENUM_FAILED"}}, {up, {Matched: false, StatisticsRead: true, OperStatus: 1, MediaState: 1}}, {up, {Matched: true, StatisticsRead: false, OperStatus: 1, MediaState: 1}},
	} {
		if uniqueOperationalStartupMapping(bad) {
			t.Fatal("unknown or ambiguous operational mapping accepted", bad)
		}
	}
}

// Captured 0.8.71 hardware-ID prefixes and CM states. This is not the shorter
// synthetic ID layout used by the first candidate; the inactive MI_04 retains
// Problem 10 while the distinct MI_02 really has DN_STARTED.
func capturedRevisionCDCTopology() []configuredStartupCMNode {
	return []configuredStartupCMNode{
		{Prefix: `USB\VID_05AC&PID_12AB&REV_1316&MI_01`, Service: "WINUSB", Status: "0x0180600a", ScopeProven: true},
		{Prefix: `USB\VID_05AC&PID_12AB&REV_1316&MI_00`, Service: "WUDFWpdMtp", Status: "0x0180200a", ScopeProven: true},
		{Prefix: `USB\VID_05AC&PID_12AB&REV_1316&CDC_0D&MI_04`, Service: "UsbNcm", Problem: 10, Status: "0x01802400", ScopeProven: true},
		{Prefix: `USB\VID_05AC&PID_12AB&REV_1316&CDC_0D&MI_02`, Service: "UsbNcm", Status: "0x0180200a", ScopeProven: true},
		{Prefix: `USB\VID_05AC&PID_12AB`, Service: "usbccgp", Status: "0x0180600a", EnumeratorClass: "020000", Root: true},
	}
}

func TestCapturedRevisionCDCTopologyPreservesIndependentCMRootProof(t *testing.T) {
	base := capturedRevisionCDCTopology()
	e := configuredStartupCMProof(base)
	if problem := configuredCMFailureReason(e); problem != "" || e.StartedControls != 1 {
		t.Fatal("captured REV/CDC topology not recognized", e, problem)
	}
	for _, tc := range []struct {
		name   string
		change func([]configuredStartupCMNode) []configuredStartupCMNode
		want   string
	}{
		{"different VID", func(n []configuredStartupCMNode) []configuredStartupCMNode {
			n[3].Prefix = `USB\VID_15AC&PID_12AB&REV_1316&CDC_0D&MI_02`
			return n
		}, "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID"},
		{"different PID", func(n []configuredStartupCMNode) []configuredStartupCMNode {
			n[3].Prefix = `USB\VID_05AC&PID_12AC&REV_1316&CDC_0D&MI_02`
			return n
		}, "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID"},
		{"different root", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[3].ScopeProven = false; return n }, "CONFIGURED_CM_NODE_ROOT_RELATIONSHIP_UNPROVEN"},
		{"duplicate MI02 instead of MI04", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[2].Prefix = n[3].Prefix; return n }, "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID"},
		{"third duplicate MI04", func(n []configuredStartupCMNode) []configuredStartupCMNode { return append(n, n[2]) }, "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID"},
		{"duplicate MI02 with a different service", func(n []configuredStartupCMNode) []configuredStartupCMNode {
			other := n[3]
			other.Service = "WINUSB"
			return append(n, other)
		}, "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID"},
		{"orphan MI03 with REV CDC", func(n []configuredStartupCMNode) []configuredStartupCMNode {
			return append(n, configuredStartupCMNode{Prefix: `USB\VID_05AC&PID_12AB&REV_1316&CDC_0D&MI_03`, Status: "0x01802400", ScopeProven: true})
		}, "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID"},
		{"orphan MI05 with REV", func(n []configuredStartupCMNode) []configuredStartupCMNode {
			return append(n, configuredStartupCMNode{Prefix: `USB\VID_05AC&PID_12AB&REV_1316&MI_05`, Status: "0x01802400", ScopeProven: true})
		}, "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID"},
		{"different root WPD node", func(n []configuredStartupCMNode) []configuredStartupCMNode { n[1].ScopeProven = false; return n }, "CONFIGURED_CM_NODE_ROOT_RELATIONSHIP_UNPROVEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := configuredStartupCMProof(tc.change(append([]configuredStartupCMNode(nil), base...)))
			if reason := configuredCMFailureReason(e); reason != tc.want {
				t.Fatalf("got %s want %s: %+v", reason, tc.want, e)
			}
			if tc.want == "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID" && !e.AllControlsSameRoot {
				t.Fatal("hardware-ID parse failure was confused with native parent-chain failure")
			}
		})
	}
}

func TestUSBHardwareIDTokensAreWholeUniqueAndBounded(t *testing.T) {
	for _, prefix := range []string{
		`USB\VID_05AC&PID_12AB&MI_02`,
		`USB\VID_05AC&PID_12AB&REV_1316&CDC_0D&MI_02`,
		`usb\vid_05ac&pid_12ab&rev_1316&cdc_0d&mi_02`,
	} {
		if mi, ok := configuredUSBInterface(prefix); !ok || mi != "02" {
			t.Fatal("valid whole-token ID rejected", prefix, mi)
		}
	}
	for _, prefix := range []string{
		`OTHER\VID_05AC&PID_12AB&MI_02`,
		`USB\VID_05AC0&PID_12AB&MI_02`,
		`USB\VID_05AC&PID_12AB0&MI_02`,
		`USB\VID_05AC&PID_12AB&REV_131G&MI_02`,
		`USB\VID_05AC&PID_12AB&REV_131&MI_02`,
		`USB\VID_05AC&PID_12AB&CDC_0E&MI_02`,
		`USB\VID_05AC&PID_12AB&MI_02&REV_1316`,
		`USB\VID_05AC&PID_12AB&MI_02&MI_04`,
		`USB\VID_05AC&PID_12AB&REV_1316&REV_1316&MI_02`,
		`USB\VID_05AC&PID_12AB&CDC_0D&CDC_0D&MI_02`,
		`USB\VID_05AC&PID_12AB&MI_020`,
		`USB\VID_05AC&PID_12AB&MI_02\INSTANCE`,
		`USB\VID_05AC&PID_12AB&FAKE_00&MI_02`,
		`USB\VID_05AC&PID_12AB&CDC_0D`,
	} {
		if _, ok := configuredUSBInterface(prefix); ok {
			t.Fatal("ambiguous or partial token accepted", prefix)
		}
	}
}
