package netconfig

import (
	"context"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func shadowTestScope() FirewallShadowScope {
	return FirewallShadowScope{Role: "host", Proof: usbaddress.InterfaceProof{Index: 12, LUID: 90, GUID: usbaddress.HostGUID, Role: "host", Created: 1}, Executable: `C:\Program Files\USB Link\0.8.118\USB-Link.exe`, PID: 21, Creation: 99, ConnectionEpoch: 1, SourceSHA256: strings.Repeat("a", 64)}
}
func TestShadowLegacyContractDoesNotReuseResidentMacMarkers(t *testing.T) {
	s := shadowTestScope()
	s.Role = "mac"
	s.Proof.Role = ""
	s.Proof.GUID = "{A4611646-E050-4D25-B83E-633A5598F302}"
	s.MacToken = strings.Repeat("a", 24)
	specs := shadowLegacySpecs(s, "USB Link")
	if len(specs) != 5 {
		t.Fatal(len(specs))
	}
	if specs[0].display != "USB Link ping" || specs[1].display != "USB Link bounded throughput test" {
		t.Fatal("legacy display contract")
	}
	for _, v := range specs {
		if v.fields["Grouping"][0] != "" || v.fields["Description"][0] != "" || v.fields["ServiceName"][0] != "" || v.fields["ApplicationName"][0] != "" {
			t.Fatal("resident marker or service wildcard invented")
		}
	}
	if specs[0].fields["IcmpTypesAndCodes"][0] != "8:*" {
		t.Fatal("ICMP echo scope")
	}
	if _, ok := specs[0].fields["LocalPorts"]; ok {
		t.Fatal("ICMP nonapplicable port")
	}
	if specs[1].fields["Profiles"][0] != "2147483647" || specs[1].fields["Action"][0] != "1" {
		t.Fatal("CIM enums leaked")
	}
}
func TestShadowUnspecifiedServiceIsNotServiceOnlyWildcard(t *testing.T) {
	if shadowSame("ServiceName", []string{"*"}, []string{""}) {
		t.Fatal("service-only wildcard broadened")
	}
	if shadowSame("ApplicationName", []string{"*"}, []string{""}) {
		t.Fatal("unproved optional-string projection")
	}
	if !shadowSame("LocalPorts", []string{"48010,47984,47989"}, []string{"47984,47989,48010"}) {
		t.Fatal("port set ordering")
	}
	if shadowSame("LocalPorts", []string{"48010,47984,47989,9999"}, []string{"47984,47989,48010"}) {
		t.Fatal("extra port accepted")
	}
}
func TestShadowSourceAndActualEpochBinding(t *testing.T) {
	s := shadowTestScope()
	if !shadowValidScope(s) {
		t.Fatal("valid")
	}
	key, series := shadowKeys(s)
	s.ConnectionEpoch++
	next, nextSeries := shadowKeys(s)
	if next == key || nextSeries != series {
		t.Fatal("actual epoch")
	}
	s.SourceSHA256 = strings.Repeat("b", 64)
	_, changed := shadowKeys(s)
	if changed == series {
		t.Fatal("source change must reset")
	}
	s.PID = 0
	if shadowValidScope(s) {
		t.Fatal("unbound source")
	}
	s = shadowTestScope()
	s.SourceSHA256 = strings.Repeat("G", 64)
	if shadowValidScope(s) {
		t.Fatal("invalid hash")
	}
	s = shadowTestScope()
	s.Role = "core_ipad"
	if shadowValidScope(s) {
		t.Fatal("cannot manufacture iPad ownership from host")
	}
}
func TestShadowMissingCoverageCannotEarnTakeover(t *testing.T) {
	var r FirewallShadowRoleDiagnostics
	for i := 0; i < 5; i++ {
		updateShadowCounters(&r, FirewallShadowSample{AllComparedAgree: true})
	}
	if r.ConsecutiveComparedAgree != 5 || r.ConsecutiveCompleteAgree != 0 || r.TakeoverEligible {
		t.Fatal(r)
	}
	for i := 0; i < 5; i++ {
		updateShadowCounters(&r, FirewallShadowSample{AllComparedAgree: true, CoverageComplete: true})
	}
	if !r.TakeoverEligible {
		t.Fatal("fifth complete actual sample boundary")
	}
	updateShadowCounters(&r, FirewallShadowSample{})
	if r.TakeoverEligible || r.ConsecutiveCompleteAgree != 0 {
		t.Fatal("mismatch resets")
	}
}
func TestShadowSnapshotNeverObservesOrExposesMutableBuffers(t *testing.T) {
	shadowState.Lock()
	old := shadowState.roles
	shadowState.roles = map[string]*shadowSeries{"host": {report: FirewallShadowRoleDiagnostics{Role: "host", DistinctConnections: 3, Last: &FirewallShadowSample{Rules: []FirewallShadowRule{{Fields: []FirewallShadowField{{Actual: []string{"original"}}}}}}}}}
	shadowState.Unlock()
	defer func() { shadowState.Lock(); shadowState.roles = old; shadowState.Unlock() }()
	a := FirewallShadowDiagnostics()
	a[0].Last.Rules[0].Fields[0].Actual[0] = "changed"
	b := FirewallShadowDiagnostics()
	if b[0].DistinctConnections != 3 || b[0].Last.Rules[0].Fields[0].Actual[0] != "original" {
		t.Fatal("snapshot mutates or increments")
	}
}
func TestShadowDefaultOffIsNoOpAndSensitiveFieldsRedacted(t *testing.T) {
	SetFirewallShadowEnabled(false)
	s := shadowTestScope()
	called := false
	ObserveLegacyFirewallShadow(context.Background(), s, func() error { called = true; return nil })
	if called {
		t.Fatal("default OFF performs reads")
	}
	for _, member := range []string{"LocalUserAuthorizedList", "RemoteMachineAuthorizedList", "LocalUserOwner", "Description", "Grouping"} {
		if !shadowRedacted(member, s) {
			t.Fatal(member)
		}
	}
	if shadowRedacted("ApplicationName", s) {
		t.Fatal("explicit bounded path debugging unavailable")
	}
}

func TestShadowActualEventDeduplicationAndBoundedAdmission(t *testing.T) {
	shadowState.Lock()
	old := shadowState.roles
	shadowState.roles = map[string]*shadowSeries{}
	shadowState.Unlock()
	defer func() {
		SetFirewallShadowEnabled(false)
		shadowState.Lock()
		shadowState.roles = old
		shadowState.Unlock()
	}()
	SetFirewallShadowEnabled(true)
	s := shadowTestScope()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Canceled context guarantees no live COM reads, including on Windows.
	ObserveLegacyFirewallShadow(ctx, s, func() error { return nil })
	ObserveLegacyFirewallShadow(ctx, s, func() error { return nil })
	r := FirewallShadowDiagnostics()
	if len(r) != 1 || r[0].DistinctConnections != 1 || r[0].DuplicateObservations != 1 || r[0].TakeoverEligible {
		t.Fatal(r)
	}
	for i := uint64(2); i <= 130; i++ {
		s.ConnectionEpoch = i
		ObserveLegacyFirewallShadow(ctx, s, func() error { return nil })
	}
	r = FirewallShadowDiagnostics()
	if r[0].DistinctConnections != 128 || r[0].ConsecutiveCompleteAgree != 0 {
		t.Fatal(r)
	}
	s.SourceSHA256 = strings.Repeat("b", 64)
	ObserveLegacyFirewallShadow(ctx, s, func() error { return nil })
	r = FirewallShadowDiagnostics()
	if r[0].DistinctConnections != 129 {
		t.Fatal("new source admission", r)
	}
}

func TestShadowSamePermissionSeriesAcrossRecreatedActualMappings(t *testing.T) {
	shadowState.Lock()
	old := shadowState.roles
	shadowState.roles = map[string]*shadowSeries{}
	shadowState.Unlock()
	defer func() { shadowState.Lock(); shadowState.roles = old; shadowState.Unlock() }()
	s := shadowTestScope()
	firstKey, firstSeries := shadowKeys(s)
	for i := uint64(1); i <= 5; i++ {
		s.Proof.Index = uint32(30 + i)
		s.Proof.LUID = 200 + i
		s.Proof.Created = int64(400 + i)
		s.PID = uint32(50 + i)
		s.Creation = 600 + i
		s.ConnectionEpoch = i
		key, series := shadowKeys(s)
		if key == firstKey || series != firstSeries {
			t.Fatal("ephemeral mapping/source process changed stable permission scope")
		}
		r, ok := beginFirewallShadowObservation(s)
		if !ok {
			t.Fatal("new actual binding not admitted")
		}
		finishFirewallShadowObservation(r, FirewallShadowSample{AllComparedAgree: true})
	}
	r := FirewallShadowDiagnostics()[0]
	if r.DistinctConnections != 5 || r.ConsecutiveComparedAgree != 5 || r.TakeoverEligible {
		t.Fatal(r)
	}
	if _, ok := beginFirewallShadowObservation(s); ok {
		t.Fatal("same connection observation counted twice")
	}
	if FirewallShadowDiagnostics()[0].ConsecutiveComparedAgree != 5 {
		t.Fatal("repeat read changed series")
	}
}
func TestShadowIPadStableScopeIgnoresLifecycleButPreservesRootPeerAndSource(t *testing.T) {
	s := shadowTestScope()
	s.Role = "ipad"
	s.Proof.Role = ""
	s.IPadPlan.GUID = s.Proof.GUID
	s.IPadPlan.Index = s.Proof.Index
	s.IPadPlan.LUID = s.Proof.LUID
	s.IPadPlan.ServerIP = "10.6.9.1"
	s.IPadPlan.Version = 4
	s.IPadPlan.Token = strings.Repeat("a", 24)
	s.IPadPlan.PlannedAt = 1
	_, base := shadowKeys(s)
	ephemeral := s
	ephemeral.Proof.Index++
	ephemeral.Proof.LUID++
	ephemeral.IPadPlan.Index++
	ephemeral.IPadPlan.LUID++
	ephemeral.IPadPlan.Token = strings.Repeat("b", 24)
	ephemeral.IPadPlan.PlannedAt = 12
	ephemeral.IPadPlan.CreatedAt = 14
	ephemeral.Proof.Created = 16
	ephemeral.PID++
	ephemeral.Creation++
	ephemeral.ConnectionEpoch++
	key1, _ := shadowKeys(s)
	key2, series := shadowKeys(ephemeral)
	if key1 == key2 || base != series {
		t.Fatal("iPad lifecycle is not a new permission contract")
	}
	variants := []FirewallShadowScope{s, s, s, s, s}
	variants[0].Executable = `D:\OtherRoot\USB-Link.exe`
	variants[1].SourceSHA256 = strings.Repeat("b", 64)
	variants[2].IPadPlan.Version = 2
	variants[3].IPadPlan.ServerIP = "10.6.10.1"
	variants[4].Proof.GUID = "{A4611646-E050-4D25-B83E-633A5598F302}"
	for i, v := range variants {
		_, changed := shadowKeys(v)
		if changed == base {
			t.Fatalf("stable root/source/peer/address/GUID difference ignored %d", i)
		}
	}
}
func TestShadowChangedPermissionContractResetsProductionSeriesCounters(t *testing.T) {
	shadowState.Lock()
	old := shadowState.roles
	shadowState.roles = map[string]*shadowSeries{}
	shadowState.Unlock()
	defer func() { shadowState.Lock(); shadowState.roles = old; shadowState.Unlock() }()
	s := shadowTestScope()
	for i := uint64(1); i <= 5; i++ {
		s.ConnectionEpoch = i
		r, ok := beginFirewallShadowObservation(s)
		if !ok {
			t.Fatal("admit")
		}
		finishFirewallShadowObservation(r, FirewallShadowSample{AllComparedAgree: true})
	}
	for _, change := range []func(*FirewallShadowScope){func(v *FirewallShadowScope) { v.Executable = `D:\OtherRoot\USB-Link.exe` }, func(v *FirewallShadowScope) { v.SourceSHA256 = strings.Repeat("b", 64) }, func(v *FirewallShadowScope) { v.Proof.GUID = "{A4611646-E050-4D25-B83E-633A5598F302}" }} {
		change(&s)
		r, ok := beginFirewallShadowObservation(s)
		if !ok {
			t.Fatal("changed contract not admitted")
		}
		if r.report.ConsecutiveComparedAgree != 0 || r.report.ConsecutiveCompleteAgree != 0 {
			t.Fatal("prior contract carried over")
		}
		finishFirewallShadowObservation(r, FirewallShadowSample{AllComparedAgree: true})
		if r.report.ConsecutiveComparedAgree != 1 {
			t.Fatal("first new contract not restarted")
		}
	}
}

func TestShadowDegenerateIPv4AddressRangesAreEquivalentOnly(t *testing.T) {
	for _, member := range []string{"LocalAddresses", "RemoteAddresses"} {
		actual, expected := []string{"10.6.9.1-10.6.9.1"}, []string{"10.6.9.1"}
		if !shadowSame(member, actual, expected) {
			t.Fatal(member, "valid equal-endpoint range")
		}
		if actual[0] != "10.6.9.1-10.6.9.1" || expected[0] != "10.6.9.1" {
			t.Fatal("raw diagnostic values changed")
		}
		for _, bad := range []string{"10.6.9.1-10.6.9.2", "10.6.9.2-10.6.9.1", "10.6.9.2-10.6.9.2", "010.6.9.1-010.6.9.1", "256.6.9.1-256.6.9.1", "10.6.9.1 -10.6.9.1", "10.6.9.1- 10.6.9.1", "10.6.9.1-10.6.9.1,10.6.9.2", "10.6.9.1-10.6.9.1-10.6.9.1", "10.6.9.1/32-10.6.9.1/32", "::ffff:10.6.9.1-::ffff:10.6.9.1", "::-::", "*-*", "Any", "LocalSubnet", ""} {
			if shadowSame(member, []string{bad}, expected) {
				t.Fatalf("%s broadened %q", member, bad)
			}
		}
		for _, badExpected := range []string{"*", "Any", "10.6.9.1/32", "10.6.9.1,10.6.9.2", "::ffff:10.6.9.1", "10.6.9.1-10.6.9.1", ""} {
			if shadowSame(member, actual, []string{badExpected}) && badExpected != actual[0] {
				t.Fatalf("unexpected equivalence %q", badExpected)
			}
		}
		if shadowSame(member, []string{actual[0], "10.6.9.2"}, expected) {
			t.Fatal("list accepted as singleton")
		}
	}
	if shadowSame("ApplicationName", []string{"10.6.9.1-10.6.9.1"}, []string{"10.6.9.1"}) || shadowSame("LocalPorts", []string{"1-1"}, []string{"1"}) {
		t.Fatal("equivalence escaped address fields")
	}
}
