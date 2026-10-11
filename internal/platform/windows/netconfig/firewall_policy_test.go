package netconfig

import (
	"errors"
	"maps"
	"slices"
	"testing"
)

func firewallPolicyFixture() (nativeRuleSpec, firewallConstraints) {
	s := nativeRuleSpec{Name: "fixed-rule", Display: "USB Link fixed", Group: "fixed-group", Description: "fixed-marker", Program: `C:\owned\USB-Link.exe`, Service: "Any", Alias: "USB Link Host", Local: "10.6.9.1", Remote: "10.6.9.2", Ports: "445,47775", RemotePorts: "Any", Protocol: 6}
	// Explicit provider-shaped values, not generated from the expected policy.
	got := firewallConstraints{
		"/InstanceID": {"S:fixed-rule"}, "/DisplayName": {"S:USB Link fixed"}, "/ElementName": {"S:USB Link fixed"}, "/PackageFamilyName": {"S:"}, "/PolicyAppId": {"S:"}, "/RuleGroup": {"S:fixed-group"}, "/Description": {"S:fixed-marker"},
		"/Enabled": {"N:1"}, "/Direction": {"N:1"}, "/Action": {"N:2"}, "/Profiles": {"N:0"}, "/Platforms": {}, "/EdgeTraversalPolicy": {"N:0"},
		"/LooseSourceMapping": {"B:false"}, "/LocalOnlyMapping": {"B:false"}, "/Owner": {"S:"},
		"MSFT_NetApplicationFilter/AppPath": {`S:C:\owned\USB-Link.exe`}, "MSFT_NetApplicationFilter/Package": {"S:"},
		"MSFT_NetAddressFilter/LocalAddress": {"S:10.6.9.1"}, "MSFT_NetAddressFilter/RemoteAddress": {"S:10.6.9.2"},
		"MSFT_NetProtocolPortFilter/Protocol": {"N:6"}, "MSFT_NetProtocolPortFilter/LocalPort": {"S:445", "S:47775"},
		"MSFT_NetProtocolPortFilter/RemotePort": {"S:Any"}, "MSFT_NetProtocolPortFilter/IcmpType": {"S:Any"}, "MSFT_NetProtocolPortFilter/DynamicTransport": {"N:0"},
		"MSFT_NetInterfaceFilter/InterfaceAlias": {"S:USB Link Host"}, "MSFT_NetInterfaceTypeFilter/InterfaceType": {"N:0"}, "MSFT_NetServiceFilter/ServiceName": {"S:Any"},
		"MSFT_NetNetworkLayerSecurityFilter/Authentication": {"N:0"}, "MSFT_NetNetworkLayerSecurityFilter/Encryption": {"N:0"},
		"MSFT_NetNetworkLayerSecurityFilter/OverrideBlockRules": {"B:false"}, "MSFT_NetNetworkLayerSecurityFilter/LocalUsers": {"S:"},
		"MSFT_NetNetworkLayerSecurityFilter/RemoteUsers": {"S:"}, "MSFT_NetNetworkLayerSecurityFilter/RemoteMachines": {"S:"},
		"/RemoteDynamicKeywordAddresses": {}, "/dynamic_source": {"S:ADDRESS"},
	}
	return s, got
}

func TestNativeFirewallCompleteScopeRequired(t *testing.T) {
	s, good := firewallPolicyFixture()
	if err := verifyFirewallConstraints(good, s, 1); err != nil {
		t.Fatal(err)
	}
	for _, group := range firewallGroups {
		for _, field := range group.fields {
			if _, exists := good[firewallField(group.class, field)]; !exists {
				t.Fatalf("uncovered constraint %s/%s", group.class, field)
			}
		}
	}
	for field := range good {
		t.Run(field, func(t *testing.T) {
			changed := maps.Clone(good)
			changed[field] = []string{"S:foreign"}
			if err := verifyFirewallConstraints(changed, s, 1); err == nil {
				t.Fatal("changed constraint accepted")
			}
			delete(changed, field)
			if err := verifyFirewallConstraints(changed, s, 1); err == nil {
				t.Fatal("missing constraint accepted")
			}
		})
	}
	extra := maps.Clone(good)
	extra["/unknown"] = []string{"S:"}
	if err := verifyFirewallConstraints(extra, s, 1); err == nil {
		t.Fatal("unknown field accepted")
	}
	// Old Program is not authorized by unchanged Group/Description markers.
	old := maps.Clone(good)
	old["MSFT_NetApplicationFilter/AppPath"] = []string{`S:C:\old\USB-Link.exe`}
	if err := verifyFirewallConstraints(old, s, 1); err == nil {
		t.Fatal("old program adopted")
	}
}

func TestNativeFirewallExplicitAbsenceAndICMP(t *testing.T) {
	s, got := firewallPolicyFixture()
	for _, field := range []string{"/Platforms", "/Owner", "/PackageFamilyName", "/PolicyAppId", "MSFT_NetApplicationFilter/Package", "/RemoteDynamicKeywordAddresses", "MSFT_NetProtocolPortFilter/IcmpType"} {
		got[field] = []string{"NULL"}
	}
	if err := verifyFirewallConstraints(got, s, 1); err != nil {
		t.Fatal(err)
	}
	s.Protocol = 1
	got["MSFT_NetProtocolPortFilter/Protocol"] = []string{"N:1"}
	if err := verifyFirewallConstraints(got, s, 1); err == nil {
		t.Fatal("null ICMP restriction adopted")
	}
	got["MSFT_NetProtocolPortFilter/IcmpType"] = []string{"S:8"}
	if err := verifyFirewallConstraints(got, s, 1); err != nil {
		t.Fatal(err)
	}
	got["MSFT_NetProtocolPortFilter/IcmpType"] = []string{"S:8", "S:8"}
	if err := verifyFirewallConstraints(got, s, 1); err == nil {
		t.Fatal("duplicate ICMP restriction accepted")
	}
}

func TestNativeFirewallReuseFreshProofs(t *testing.T) {
	s, good := firewallPolicyFixture()
	baseline, err := firewallFingerprint(good)
	if err != nil {
		t.Fatal(err)
	}
	for _, cached := range []string{"", baseline} {
		reads, proofs := 0, 0
		hash, err := verifyNativeRuleReuse(s, cached, func() (firewallConstraints, error) { reads++; return maps.Clone(good), nil }, func() error { proofs++; return nil })
		if err != nil || hash != baseline || reads != 2 || proofs != 3 {
			t.Fatalf("cold/warm proof incomplete: %q %v %d %d", hash, err, reads, proofs)
		}
	}
	for _, mode := range []string{"old-program", "missing-filter", "second-read-changed", "cached-projection-changed", "nic-before", "nic-between", "nic-after"} {
		t.Run(mode, func(t *testing.T) {
			reads, proofs := 0, 0
			cached := ""
			if mode == "cached-projection-changed" {
				cached = baseline
			}
			hash, err := verifyNativeRuleReuse(s, cached, func() (firewallConstraints, error) {
				reads++
				got := maps.Clone(good)
				switch mode {
				case "old-program":
					got["MSFT_NetApplicationFilter/AppPath"] = []string{`S:C:\old\USB-Link.exe`}
				case "missing-filter":
					return nil, errors.New("filter unproven")
				case "second-read-changed":
					if reads == 2 {
						got["/Owner"] = []string{"NULL"}
					}
				case "cached-projection-changed":
					got["/Owner"] = []string{"NULL"}
				}
				return got, nil
			}, func() error {
				proofs++
				if (mode == "nic-before" && proofs == 1) || (mode == "nic-between" && proofs == 2) || (mode == "nic-after" && proofs == 3) {
					return errors.New("NIC changed")
				}
				return nil
			})
			if err == nil || hash != "" {
				t.Fatal("unproven reuse published")
			}
		})
	}
}

func TestNativeFirewallDisabledRuleRequiresStableReadbacks(t *testing.T) {
	s, disabled := firewallPolicyFixture()
	disabled["/Enabled"] = []string{"N:2"}
	if _, err := verifyNativeRuleReuse(s, "", func() (firewallConstraints, error) { return disabled, nil }, func() error { return nil }); err == nil {
		t.Fatal("disabled rule reused as enabled")
	}
	reads := 0
	if _, err := verifyNativeRuleReadbacks(s, 2, "", func() (firewallConstraints, error) { reads++; return maps.Clone(disabled), nil }, func() error { return nil }); err != nil || reads != 2 {
		t.Fatalf("disabled readback failed %v/%d", err, reads)
	}
	reads = 0
	if _, err := verifyNativeRuleReadbacks(s, 2, "", func() (firewallConstraints, error) {
		reads++
		got := maps.Clone(disabled)
		if reads == 2 {
			got["/Owner"] = []string{"NULL"}
		}
		return got, nil
	}, func() error { return nil }); err == nil {
		t.Fatal("changing disabled rule may be enabled")
	}
}

// The .107 read-only Windows baseline reported the default Any interface as
// CIM 0, NULL optional remote port/service, and NULL unrestricted principals.
// These are field- and expectation-specific projections, not absent proofs.
func TestNativeFirewallActualDefaultProjections(t *testing.T) {
	s, got := firewallPolicyFixture()
	keys := []string{"MSFT_NetProtocolPortFilter/RemotePort", "MSFT_NetServiceFilter/ServiceName", "MSFT_NetNetworkLayerSecurityFilter/LocalUsers", "MSFT_NetNetworkLayerSecurityFilter/RemoteUsers", "MSFT_NetNetworkLayerSecurityFilter/RemoteMachines"}
	for _, key := range keys {
		got[key] = []string{"NULL"}
	}
	if err := verifyFirewallConstraints(got, s, 1); err != nil {
		t.Fatal(err)
	}
	if !nativeReadStageFieldsMatch(nativeFirewallReadDifferences(s, got, nil)) {
		t.Fatal("diagnostic and runtime contracts disagree")
	}
	for _, n := range []string{"N:1", "N:2", "N:4", "N:7", "N:99", "NULL"} {
		bad := maps.Clone(got)
		bad["MSFT_NetInterfaceTypeFilter/InterfaceType"] = []string{n}
		if verifyFirewallConstraints(bad, s, 1) == nil {
			t.Fatalf("Any intent adopted another interface type: %s", n)
		}
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			expected := expectedFirewallConstraints(s, 1)[key]
			if !firewallDefaultMatches(key, []string{"NULL"}, expected, s.Protocol, got) {
				t.Fatal("specific default projection rejected")
			}
			if firewallDefaultMatches(key, []string{"NULL"}, []string{"S:restricted"}, s.Protocol, got) {
				t.Fatal("NULL accepted for a nonempty specific restriction")
			}
			for _, invalid := range [][]string{nil, {"S:unknown"}, {"NULL", "NULL"}} {
				if firewallDefaultMatches(key, invalid, expected, s.Protocol, got) {
					t.Fatal("unproven projection accepted")
				}
			}
			missing := maps.Clone(got)
			delete(missing, key)
			if verifyFirewallConstraints(missing, s, 1) == nil {
				t.Fatal("missing property accepted as NULL")
			}
		})
	}
	for _, field := range []string{"MSFT_NetNetworkLayerSecurityFilter/Authentication", "MSFT_NetNetworkLayerSecurityFilter/Encryption", "MSFT_NetNetworkLayerSecurityFilter/OverrideBlockRules", "/Action"} {
		bad := maps.Clone(got)
		bad[field] = []string{"N:1"}
		if field == "MSFT_NetNetworkLayerSecurityFilter/OverrideBlockRules" {
			bad[field] = []string{"B:true"}
		}
		if field == "/Action" {
			bad[field] = []string{"N:3"}
		}
		if verifyFirewallConstraints(bad, s, 1) == nil {
			t.Fatal("changed security policy accepted")
		}
		if firewallDefaultMatches("MSFT_NetNetworkLayerSecurityFilter/LocalUsers", []string{"NULL"}, []string{"S:"}, s.Protocol, bad) {
			t.Fatal("NULL principal accepted without exact ordinary Allow security gates")
		}
		delete(bad, field)
		if firewallDefaultMatches("MSFT_NetNetworkLayerSecurityFilter/LocalUsers", []string{"NULL"}, []string{"S:"}, s.Protocol, bad) {
			t.Fatal("missing security gate accepted")
		}
	}
	for _, restricted := range []string{"port", "service"} {
		want, actual := s, maps.Clone(got)
		if restricted == "port" {
			want.RemotePorts = "443"
		} else {
			want.Service = "LanmanServer"
		}
		if verifyFirewallConstraints(actual, want, 1) == nil {
			t.Fatalf("NULL adopted specific %s", restricted)
		}
	}
}

func TestNativeFirewallDefaultProjectionFingerprintsRemainExact(t *testing.T) {
	s, normal := firewallPolicyFixture()
	for _, key := range []string{"MSFT_NetProtocolPortFilter/RemotePort", "MSFT_NetServiceFilter/ServiceName", "MSFT_NetNetworkLayerSecurityFilter/LocalUsers", "MSFT_NetNetworkLayerSecurityFilter/RemoteUsers", "MSFT_NetNetworkLayerSecurityFilter/RemoteMachines"} {
		t.Run(key, func(t *testing.T) {
			alternate := maps.Clone(normal)
			alternate[key] = []string{"NULL"}
			originalHash, _ := firewallFingerprint(normal)
			alternateHash, _ := firewallFingerprint(alternate)
			if originalHash == alternateHash {
				t.Fatal("NULL canonicalized into ordinary default")
			}
			if _, err := verifyNativeRuleReuse(s, originalHash, func() (firewallConstraints, error) { return alternate, nil }, func() error { return nil }); err == nil {
				t.Fatal("warm fingerprint drift accepted")
			}
			reads := 0
			if _, err := verifyNativeRuleReuse(s, "", func() (firewallConstraints, error) {
				reads++
				if reads == 1 {
					return normal, nil
				}
				return alternate, nil
			}, func() error { return nil }); err == nil {
				t.Fatal("changing cold read projection accepted")
			}
			if _, err := verifyNativeRuleReuse(s, "", func() (firewallConstraints, error) { return alternate, nil }, func() error { return nil }); err != nil {
				t.Fatal("stable full cold default projection rejected", err)
			}
		})
	}
}

func TestNativeFirewallICMPPortApplicability(t *testing.T) {
	const local = "MSFT_NetProtocolPortFilter/LocalPort"
	const remote = "MSFT_NetProtocolPortFilter/RemotePort"
	s, base := firewallPolicyFixture()
	s.Protocol, s.Ports, s.RemotePorts, s.ICMP = 1, "Any", "Any", "8"
	base["MSFT_NetProtocolPortFilter/Protocol"] = []string{"N:1"}
	base[local], base[remote] = []string{"NULL"}, []string{"NULL"}
	base["MSFT_NetProtocolPortFilter/IcmpType"] = []string{"S:8"}
	if verifyFirewallConstraints(base, s, 1) != nil {
		t.Fatal("explicit ignored port NULL rejected for exact ICMP echo scope")
	}
	for _, protocol := range []int32{1, 58} {
		for _, key := range []string{local, remote} {
			if !firewallDefaultMatches(key, []string{"NULL"}, []string{"S:Any"}, protocol, base) {
				t.Fatal("ICMP ignored port projection rejected")
			}
			if firewallDefaultMatches(key, []string{"NULL"}, []string{"S:443"}, protocol, base) {
				t.Fatal("specific port restriction interpreted as ignored")
			}
			if firewallDefaultMatches(key, nil, []string{"S:Any"}, protocol, base) {
				t.Fatal("unproven absence interpreted as explicit NULL")
			}
		}
	}
	for _, protocol := range []int32{0, 6, 17, 47, 255} {
		if firewallDefaultMatches(local, []string{"NULL"}, []string{"S:Any"}, protocol, base) {
			t.Fatal("non-ICMP local port NULL accepted")
		}
	}
	for _, protocol := range []int32{0, 47, 255} {
		if firewallDefaultMatches(remote, []string{"NULL"}, []string{"S:Any"}, protocol, base) {
			t.Fatal("unknown protocol port exemption")
		}
	}
	for _, change := range []string{local, remote, "MSFT_NetProtocolPortFilter/IcmpType"} {
		bad := maps.Clone(base)
		delete(bad, change)
		if verifyFirewallConstraints(bad, s, 1) == nil {
			t.Fatal("missing ICMP constraint accepted")
		}
	}
	bad := maps.Clone(base)
	bad["MSFT_NetProtocolPortFilter/IcmpType"] = []string{"NULL"}
	if verifyFirewallConstraints(bad, s, 1) == nil {
		t.Fatal("missing exact echo-type restriction accepted")
	}
	anyPorts := maps.Clone(base)
	anyPorts[local], anyPorts[remote] = []string{"S:Any"}, []string{"S:Any"}
	firstHash, _ := firewallFingerprint(base)
	secondHash, _ := firewallFingerprint(anyPorts)
	if firstHash == secondHash {
		t.Fatal("ICMP NULL/Any ports fingerprint canonicalized")
	}
	reads := 0
	if _, err := verifyNativeRuleReuse(s, "", func() (firewallConstraints, error) {
		reads++
		if reads == 1 {
			return base, nil
		}
		return anyPorts, nil
	}, func() error { return nil }); err == nil {
		t.Fatal("changing ignored port projection accepted")
	}
	fields, err := nativeFirewallPortWriteFields(s)
	if err != nil || !slices.Equal(fields, []string{"Protocol", "IcmpType"}) {
		t.Fatal("ICMP factory would write inapplicable ports", fields, err)
	}
	for _, mutation := range []string{"local", "remote", "type", "v6", "v6-explicit", "unknown"} {
		bad := s
		switch mutation {
		case "local":
			bad.Ports = "443"
		case "remote":
			bad.RemotePorts = "443"
		case "type":
			bad.ICMP = "Any"
		case "v6":
			bad.Protocol, bad.ICMP = 58, ""
		case "v6-explicit":
			bad.Protocol, bad.ICMP = 58, "128"
		case "unknown":
			bad.Protocol = 47
		}
		if _, err := nativeFirewallPortWriteFields(bad); err == nil {
			t.Fatal("unsupported factory plan accepted", mutation)
		}
	}
	for _, protocol := range []int32{6, 17} {
		s.Protocol, s.ICMP = protocol, ""
		fields, err := nativeFirewallPortWriteFields(s)
		if err != nil || !slices.Equal(fields, []string{"Protocol", "LocalPort", "RemotePort"}) {
			t.Fatal("TCP/UDP port setters missing")
		}
	}
}
