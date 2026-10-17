package ipadncm

import (
	"os"
	"strings"
	"testing"
)

func TestExistingGroupingAdmissionRequiresFreshProofWithoutClaimingOriginals(t *testing.T) {
	cm := configuredStartupCMProof([]configuredStartupCMNode{
		{Prefix: `USB\VID_05AC&PID_12AB`, Service: "usbccgp", Status: "0x0180600a", EnumeratorClass: "020000", Root: true},
		{Prefix: `USB\VID_05AC&PID_12AB&MI_02`, Service: "UsbNcm", Status: "0x0180600a", ScopeProven: true},
		{Prefix: `USB\VID_05AC&PID_12AB&MI_04`, Service: "UsbNcm", Problem: 10, Status: "0x01802400", ScopeProven: true},
	})
	good := existingGroupingAdmission{Consent: true, CurrentRoot: true, Driver: true, ReceiptsAbsent: true, Mapping: true, ContextActive: true, CM: cm}
	if good.failure() != "" || good.CM.ready() || good.CM.RegistryOwned || good.CM.ReceiptValid {
		t.Fatal("live layout confused with saved registry ownership", good)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*existingGroupingAdmission)
	}{
		{"no_consent", func(e *existingGroupingAdmission) { e.Consent = false }},
		{"cancelled", func(e *existingGroupingAdmission) { e.ContextActive = false }},
		{"different_root", func(e *existingGroupingAdmission) { e.CurrentRoot = false }},
		{"driver_changed", func(e *existingGroupingAdmission) { e.Driver = false }},
		{"receipt_found_or_unreadable", func(e *existingGroupingAdmission) { e.ReceiptsAbsent = false }},
		{"unhealthy_root", func(e *existingGroupingAdmission) { e.CM.RootHealthy = false }},
		{"unreadable_control", func(e *existingGroupingAdmission) { e.CM.NodesReadable = false }},
		{"restart_needed", func(e *existingGroupingAdmission) { e.CM.NoRestart = false }},
		{"wrong_parent", func(e *existingGroupingAdmission) { e.CM.AllControlsSameRoot = false }},
		{"orphan_data", func(e *existingGroupingAdmission) { e.CM.ControlTopology = false }},
		{"no_started_control", func(e *existingGroupingAdmission) { e.CM.StartedControls = 0 }},
		{"too_many_controls", func(e *existingGroupingAdmission) { e.CM.StartedControls = 3 }},
		{"ambiguous_mapping", func(e *existingGroupingAdmission) { e.Mapping = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := good
			tc.mutate(&bad)
			if bad.failure() == "" {
				t.Fatal("incomplete live proof admitted")
			}
		})
	}
	if (startupReadiness{Controls: 2, StartedControls: 1, FailedControls: 1}).settled() {
		t.Fatal("ordinary native readiness weakened")
	}
}

// The Windows-only producer is also checked so the portable gate cannot hide
// an accidental call into the registry transaction or synthetic backup path.
func TestExistingGroupingWindowsPathCannotOwnOrRestoreRegistry(t *testing.T) {
	content, err := os.ReadFile("grouping_existing_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(content)
	for _, forbidden := range []string{"groupingJournal{", "OriginalAbsent", "registry.SET_VALUE", "SetBinaryValue", "DeleteValue", "RunPersistentGrouping(", "RunGroupingTrial(", "commitConfiguration(", ".Observe(", ".Restore(", "restartGroupingRoot", "saveGrouping", "ConfigurationRetained: true", "BackupSaved: true", "context.Background()"} {
		if strings.Contains(s, forbidden) {
			t.Fatal("existing layout gained mutation or synthetic authority", forbidden)
		}
	}
	for _, required := range []string{"registry.QUERY_VALUE", "os.IsNotExist(receiptError)", "networkOnlyUSBEligible(s)", "sameRootInstance(mode.Before, s)", "b.waitForPeerReady()", "b.runApplication(peer)"} {
		if !strings.Contains(s, required) {
			t.Fatal("required admission/session boundary missing", required)
		}
	}
	start := strings.Index(s, "func RunExistingGrouping(")
	flow := s[start:]
	if strings.Index(flow, `n.EnumeratorClass == "020000"`) > strings.Index(flow, "if !handled") || strings.Contains(flow, `root != "" && strings.EqualFold(n.instanceID`) {
		t.Fatal("ambiguous observed grouping can fall into mutation path")
	}
	if !strings.Contains(flow, "return r, true") {
		t.Fatal("rejected existing layout not handled")
	}
	if strings.Index(flow, `"EXISTING_LAYOUT_VERIFIED_SESSION_STARTING"`) > strings.Index(flow, "b.runApplication(peer)") {
		t.Fatal("live evidence only appears after session ends")
	}
	sharedStart := strings.Index(s, "func existingGroupingLiveProof(")
	mapping := s[strings.Index(s, "func (b *groupingBackend) existingNetworkMapping("):sharedStart]
	if strings.Count(mapping, "readExistingNetworkTarget(") != 2 || strings.LastIndex(mapping, "readExistingNetworkTarget(") < strings.Index(mapping, "adapters := readAdapters()") {
		t.Fatal("registry identity not rechecked after mapping")
	}
	shared := s[sharedStart:start]
	if strings.Count(shared, "readStartupOwnedGrouping(") != 2 || !strings.Contains(shared, "sameUSBTarget(mode.Before, s)") || !strings.Contains(shared, "admission.Consent = consent()") || !strings.Contains(flow, "existingGroupingLiveProof(ctx, dir, mode, s, consent)") {
		t.Fatal("shared live proof lost fresh target, receipt or consent boundary")
	}
	startup, err := os.ReadFile("startup_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(startup), "existingGroupingLiveProof(ctx, configuredDir, *mode, s, consent[0])") || strings.Contains(string(startup), "r.NetworkVerified = true") || strings.Contains(string(startup), "proof.ReceiptValid = true") || strings.Contains(string(startup), "proof.RegistryOwned = true") {
		t.Fatal("startup wait must share complete proof without creating network or registry authority")
	}
}
