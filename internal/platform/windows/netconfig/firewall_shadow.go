package netconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/ipadsession"
	"suhang/usbnet/internal/transport/usbaddress"
	"sync"
	"sync/atomic"
	"time"
)

// Shadow observations are diagnostics only. They never grant permission or
// replace legacy PowerShell's readback, repair, or readiness decisions.
type FirewallShadowScope struct {
	Role                      string
	Proof                     usbaddress.InterfaceProof
	Executable, MacToken      string
	IPadPlan                  ipadsession.Plan
	PID                       uint32
	Creation, ConnectionEpoch uint64
	SourceSHA256              string
}
type FirewallShadowField struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Actual   []string `json:"actual,omitempty"`
	Expected []string `json:"expected,omitempty"`
	Status   string   `json:"status"`
	HRESULT  uint32   `json:"hresult,omitempty"`
	Redacted bool     `json:"redacted,omitempty"`
}
type FirewallShadowRule struct {
	Selector       int                   `json:"selector"`
	CandidateCount int                   `json:"candidate_count"`
	Fields         []FirewallShadowField `json:"fields"`
}
type FirewallShadowSample struct {
	Role                      string               `json:"role"`
	ReadOnly                  bool                 `json:"read_only"`
	DecisionOwner             string               `json:"decision_owner"`
	Status                    string               `json:"status"`
	AllComparedAgree          bool                 `json:"all_compared_agree"`
	CoverageComplete          bool                 `json:"coverage_complete"`
	UnsupportedContractFields []string             `json:"unsupported_contract_fields"`
	Rules                     []FirewallShadowRule `json:"rules,omitempty"`
	DurationMS                int64                `json:"duration_ms"`
	HRESULT                   uint32               `json:"hresult,omitempty"`
}
type FirewallShadowRoleDiagnostics struct {
	Role                     string                `json:"role"`
	DistinctConnections      uint64                `json:"distinct_connections"`
	DuplicateObservations    uint64                `json:"duplicate_observations"`
	ConsecutiveComparedAgree uint64                `json:"consecutive_compared_agree"`
	ConsecutiveCompleteAgree uint64                `json:"consecutive_complete_agree"`
	TakeoverEligible         bool                  `json:"takeover_eligible"`
	Last                     *FirewallShadowSample `json:"last,omitempty"`
}

var firewallShadowEnabled atomic.Bool

func SetFirewallShadowEnabled(v bool) { firewallShadowEnabled.Store(v) }
func FirewallShadowEnabled() bool     { return firewallShadowEnabled.Load() }

var shadowState = struct {
	sync.Mutex
	roles map[string]*shadowSeries
}{roles: map[string]*shadowSeries{}}

type shadowSeries struct {
	report FirewallShadowRoleDiagnostics
	source string
	seen   map[string]bool
	busy   bool
}

// Bump whenever shadow comparison semantics change: observations of different
// comparison contracts must not accumulate in one five-connection series.
const shadowComparisonSchema = 2

var shadowUnsupported = []string{"PersistentStoreOrigin", "CIMInstanceID", "Platforms", "PolicyAppId", "LooseSourceMapping", "LocalOnlyMapping", "DynamicTransport", "RemoteDynamicKeywordAddresses", "OverrideBlockRulesIndependentProjection"}

// ObserveLegacyFirewallShadow must run in a caller-owned asynchronous goroutine.
// COM cancellation is cooperative, not a hard timeout: do not join this call
// from a connection's readiness/Close path or retain its lease/configuration lock.
func ObserveLegacyFirewallShadow(ctx context.Context, s FirewallShadowScope, owner func() error) {
	if !FirewallShadowEnabled() || ctx == nil || owner == nil || !shadowValidScope(s) {
		return
	}
	r, accepted := beginFirewallShadowObservation(s)
	if !accepted {
		return
	}
	started := time.Now()
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	sample := observeFirewallShadow(bounded, s, owner)
	sample.Role = s.Role
	sample.ReadOnly = true
	sample.DecisionOwner = "legacy_powershell"
	sample.DurationMS = time.Since(started).Milliseconds()
	// Full policy contract fields unavailable in INetFw cannot be invented from
	// a successful partial read. This deliberately prevents premature takeover.
	sample.UnsupportedContractFields = append([]string(nil), shadowUnsupported...)
	sample.CoverageComplete = false
	finishFirewallShadowObservation(r, sample)
}
func beginFirewallShadowObservation(s FirewallShadowScope) (*shadowSeries, bool) {
	key, series := shadowKeys(s)
	shadowState.Lock()
	defer shadowState.Unlock()
	r := shadowState.roles[s.Role]
	if r == nil {
		r = &shadowSeries{report: FirewallShadowRoleDiagnostics{Role: s.Role}, seen: map[string]bool{}}
		shadowState.roles[s.Role] = r
	}
	if r.busy {
		return nil, false
	}
	if r.source != series {
		r.source = series
		r.seen = map[string]bool{}
		r.report.ConsecutiveComparedAgree = 0
		r.report.ConsecutiveCompleteAgree = 0
		r.report.TakeoverEligible = false
	}
	if r.seen[key] {
		r.report.DuplicateObservations++
		return nil, false
	}
	if len(r.seen) >= 128 {
		return nil, false
	}
	r.seen[key] = true
	r.busy = true
	return r, true
}
func finishFirewallShadowObservation(r *shadowSeries, sample FirewallShadowSample) {
	shadowState.Lock()
	defer shadowState.Unlock()
	r.busy = false
	r.report.DistinctConnections++
	updateShadowCounters(&r.report, sample)
	r.report.Last = cloneShadowSample(&sample)
}
func updateShadowCounters(report *FirewallShadowRoleDiagnostics, sample FirewallShadowSample) {
	if sample.AllComparedAgree {
		report.ConsecutiveComparedAgree++
	} else {
		report.ConsecutiveComparedAgree = 0
	}
	if sample.AllComparedAgree && sample.CoverageComplete {
		report.ConsecutiveCompleteAgree++
	} else {
		report.ConsecutiveCompleteAgree = 0
	}
	report.TakeoverEligible = report.ConsecutiveCompleteAgree >= 5
}
func FirewallShadowDiagnostics() []FirewallShadowRoleDiagnostics {
	shadowState.Lock()
	defer shadowState.Unlock()
	out := []FirewallShadowRoleDiagnostics{}
	for _, role := range []string{"host", "mac", "core_mac", "ipad", "core_ipad"} {
		if r := shadowState.roles[role]; r != nil {
			v := r.report
			v.Last = cloneShadowSample(v.Last)
			out = append(out, v)
		}
	}
	return out
}
func cloneShadowSample(v *FirewallShadowSample) *FirewallShadowSample {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	var n FirewallShadowSample
	_ = json.Unmarshal(b, &n)
	return &n
}
func shadowValidScope(s FirewallShadowScope) bool {
	if s.PID == 0 || s.Creation == 0 || s.ConnectionEpoch == 0 || len(s.SourceSHA256) != 64 || s.Proof.Index == 0 || s.Proof.LUID == 0 || !guidPattern.MatchString(s.Proof.GUID) {
		return false
	}
	b, e := hex.DecodeString(s.SourceSHA256)
	if e != nil || len(b) != 32 || s.SourceSHA256 != strings.ToLower(s.SourceSHA256) {
		return false
	}
	switch s.Role {
	case "host":
		return s.Proof.Role == "host" && strings.EqualFold(s.Proof.GUID, usbaddress.HostGUID) && s.Proof.Created > 0 && validCoreExecutable(s.Executable)
	case "mac":
		return s.Proof.Role == "" && strings.EqualFold(s.Proof.GUID, "{A4611646-E050-4D25-B83E-633A5598F302}") && idPattern.MatchString(s.MacToken)
	case "core_mac":
		return s.Proof.Role == "" && strings.EqualFold(s.Proof.GUID, "{A4611646-E050-4D25-B83E-633A5598F302}") && validCoreExecutable(s.Executable)
	case "ipad", "core_ipad":
		return s.Proof.Role == "" && s.IPadPlan.Valid() && s.IPadPlan.ServerIP == "10.6.9.1" && strings.EqualFold(s.Proof.GUID, s.IPadPlan.GUID) && s.Proof.Index == s.IPadPlan.Index && s.Proof.LUID == s.IPadPlan.LUID && (s.Role == "ipad" || validCoreExecutable(s.Executable))
	}
	return false
}
func shadowKeys(s FirewallShadowScope) (string, string) {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	// The admission key above retains the entire fresh actual binding. The
	// comparison series below contains only permission/source invariants:
	// recreated interface mappings and session tokens cannot erase real
	// consecutive connection observations of the same compiled contract.
	stable := struct {
		ContractSchema                                                 int
		Role, GUID, Executable, SourceSHA256, IPadServerIP, IPadPeerIP string
	}{ContractSchema: shadowComparisonSchema, Role: s.Role, GUID: strings.ToLower(s.Proof.GUID),
		Executable: s.Executable, SourceSHA256: s.SourceSHA256}
	if s.Role == "ipad" || s.Role == "core_ipad" {
		stable.IPadServerIP = s.IPadPlan.ServerIP
		stable.IPadPeerIP = s.IPadPlan.PeerIP()
	}
	b, _ = json.Marshal(stable)
	series := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), hex.EncodeToString(series[:])
}

type shadowSpec struct {
	fields   map[string][]string
	protocol int
	display  string
}

func shadowLegacySpecs(s FirewallShadowScope, alias string) []shadowSpec {
	specs := []shadowSpec{}
	add := func(display, group, description, program, service, local, remote, ports, rports string, proto int) {
		if local == "Any" {
			local = "*"
		}
		if remote == "Any" {
			remote = "*"
		}
		if ports == "" || ports == "Any" {
			ports = "*"
		}
		if rports == "" || rports == "Any" {
			rports = "*"
		}
		ports = strings.ReplaceAll(ports, "'", "")
		f := map[string][]string{"Name": {display}, "Grouping": {group}, "Description": {description}, "ApplicationName": {program}, "ServiceName": {service}, "LocalAddresses": {local}, "RemoteAddresses": {remote}, "LocalPorts": {ports}, "RemotePorts": {rports}, "Interfaces": {alias}, "InterfaceTypes": {"All"}, "Protocol": {fmt.Sprint(proto)}, "Profiles": {"2147483647"}, "Direction": {"1"}, "Action": {"1"}, "Enabled": {"true"}, "EdgeTraversal": {"false"}, "EdgeTraversalOptions": {"0"}, "LocalAppPackageId": {""}, "LocalUserAuthorizedList": {""}, "LocalUserOwner": {""}, "RemoteMachineAuthorizedList": {""}, "RemoteUserAuthorizedList": {""}, "SecureFlags": {"0"}, "IcmpTypesAndCodes": {""}}
		if proto == 1 {
			f["IcmpTypesAndCodes"] = []string{"8:*"}
			delete(f, "LocalPorts")
			delete(f, "RemotePorts")
		}
		specs = append(specs, shadowSpec{f, proto, display})
	}
	core := func(peer string, host bool) {
		namePorts := securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")
		if peer == "10.6.9.2" {
			namePorts += ",47775"
		}
		add("USB Link USB services", serviceGroup, serviceMarker, s.Executable, "", "10.6.9.1", peer, namePorts, "", 6)
		add("USB Link USB services", serviceGroup, serviceMarker, "System", "LanmanServer", "10.6.9.1", peer, "445", "", 6)
		_ = host
	}
	switch s.Role {
	case "host":
		core("10.6.9.2", true)
		core("10.6.9.3", true)
	case "core_mac":
		core("10.6.9.2", false)
	case "core_ipad":
		core("10.6.9.3", false)
		add("USB Link USB services", serviceGroup, serviceMarker, s.Executable, "", "Any", "Any", "67", "68", 17)
		add("USB Link USB services", serviceGroup, serviceMarker, s.Executable, "", "Any", "Any", "5353", "", 17)
	case "mac":
		add("USB Link ping", "", "", "", "", "10.6.9.1", "10.6.9.2", "", "", 1)
		add("USB Link bounded throughput test", "", "", "", "", "10.6.9.1", "10.6.9.2", securitypolicy.Ports(securitypolicy.NativeBenchmark, "TCP"), "", 6)
		add("USB Link Sunshine TCP", "", "", "", "", "10.6.9.1", "10.6.9.2", securitypolicy.InboundPorts("mac", "TCP"), "", 6)
		add("USB Link Sunshine UDP", "", "", "", "", "10.6.9.1", "10.6.9.2", securitypolicy.InboundPorts("mac", "UDP"), "", 17)
		add("USB Link file receiver", "", "", "", "", "10.6.9.1", "10.6.9.2", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP"), "", 6)
	case "ipad":
		p := s.IPadPlan
		add("Suhang iPad USB DHCP trial", p.Prefix(), p.Marker(), "", "", "Any", "Any", "67", "68", 17)
		add("Suhang iPad USB discovery trial", p.Prefix(), p.Marker(), "", "", "Any", "Any", "5353", "", 17)
		add("Suhang iPad USB application TCP trial", p.Prefix(), p.Marker(), "", "", p.ServerIP, p.PeerIP(), securitypolicy.InboundPorts("ipad", "TCP"), "", 6)
		add("Suhang iPad USB Sunshine UDP trial", p.Prefix(), p.Marker(), "", "", p.ServerIP, p.PeerIP(), securitypolicy.InboundPorts("ipad", "UDP"), "", 17)
	}
	return specs
}
func shadowSame(name string, actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	if (name == "LocalAddresses" || name == "RemoteAddresses") && len(actual) == 1 && actual[0] != expected[0] {
		return shadowSingleIPv4Range(actual[0], expected[0])
	}
	a := append([]string(nil), actual...)
	b := append([]string(nil), expected...)
	if strings.HasSuffix(name, "Ports") {
		if len(a) != 1 {
			return false
		}
		a = strings.Split(a[0], ",")
		b = strings.Split(b[0], ",")
		for i := range a {
			a[i] = strings.TrimSpace(a[i])
		}
		for i := range b {
			b[i] = strings.TrimSpace(b[i])
		}
	}
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

// INetFwRule documents an IPv4 range as start-end, without spaces. A
// degenerate range represents exactly one IPv4 address; this is the only
// additional shape accepted here. Preserve original Actual/Expected DTO values.
func shadowSingleIPv4Range(actual, expected string) bool {
	if strings.Count(actual, "-") != 1 {
		return false
	}
	expectedIP, err := netip.ParseAddr(expected)
	if err != nil || !expectedIP.Is4() {
		return false
	}
	start, end, _ := strings.Cut(actual, "-")
	startIP, startErr := netip.ParseAddr(start)
	endIP, endErr := netip.ParseAddr(end)
	return startErr == nil && endErr == nil && startIP.Is4() && endIP.Is4() && startIP == endIP && startIP == expectedIP
}

func shadowRedacted(member string, s FirewallShadowScope) bool {
	return strings.Contains(member, "AuthorizedList") || member == "LocalUserOwner" || member == "Description" || member == "Grouping"
}
