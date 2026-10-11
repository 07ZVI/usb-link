package netconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

type nativeRuleSpec struct {
	Name, Display, Group, Description, Program, Service, Alias, Local, Remote, Ports, RemotePorts, ICMP string
	Protocol                                                                                            int32
}

type firewallGroup struct {
	class  string
	fields []string
}

// Match-affecting properties and ownership selectors; status/trace metadata and
// inherited properties explicitly ignored by the provider are not authority.
var firewallGroups = []firewallGroup{
	{"", []string{"InstanceID", "RuleGroup", "Description", "DisplayName", "ElementName", "PackageFamilyName", "PolicyAppId", "Enabled", "Direction", "Action", "Profiles", "Platforms", "EdgeTraversalPolicy", "LooseSourceMapping", "LocalOnlyMapping", "Owner"}},
	{"MSFT_NetApplicationFilter", []string{"AppPath", "Package"}},
	{"MSFT_NetAddressFilter", []string{"LocalAddress", "RemoteAddress"}},
	{"MSFT_NetProtocolPortFilter", []string{"Protocol", "LocalPort", "RemotePort", "IcmpType", "DynamicTransport"}},
	{"MSFT_NetInterfaceFilter", []string{"InterfaceAlias"}},
	{"MSFT_NetInterfaceTypeFilter", []string{"InterfaceType"}},
	{"MSFT_NetServiceFilter", []string{"ServiceName"}},
	{"MSFT_NetNetworkLayerSecurityFilter", []string{"Authentication", "Encryption", "OverrideBlockRules", "LocalUsers", "RemoteUsers", "RemoteMachines"}},
}

type firewallConstraints map[string][]string

func firewallField(class, field string) string { return class + "/" + field }

func firewallParts(values ...string) []string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = "S:" + value
	}
	sort.Strings(parts)
	return parts
}

func expectedFirewallConstraints(s nativeRuleSpec, enabled int32) firewallConstraints {
	port := "MSFT_NetProtocolPortFilter"
	want := firewallConstraints{
		"/InstanceID": firewallParts(s.Name), "/DisplayName": firewallParts(s.Display), "/ElementName": firewallParts(s.Display),
		"/PackageFamilyName": firewallParts(""), "/PolicyAppId": firewallParts(""),
		"/RuleGroup": firewallParts(s.Group), "/Description": firewallParts(s.Description),
		"/Enabled": {fmt.Sprint("N:", enabled)}, "/Direction": {"N:1"}, "/Action": {"N:2"}, "/Profiles": {"N:0"},
		"/EdgeTraversalPolicy": {"N:0"}, "/LooseSourceMapping": {"B:false"}, "/LocalOnlyMapping": {"B:false"},
		"/Platforms": {}, "/Owner": firewallParts(""),
		"MSFT_NetApplicationFilter/AppPath": firewallParts(s.Program), "MSFT_NetApplicationFilter/Package": firewallParts(""),
		"MSFT_NetAddressFilter/LocalAddress":  firewallParts(strings.Split(s.Local, ",")...),
		"MSFT_NetAddressFilter/RemoteAddress": firewallParts(strings.Split(s.Remote, ",")...),
		port + "/Protocol":                    {fmt.Sprint("N:", s.Protocol)}, port + "/LocalPort": firewallParts(strings.Split(s.Ports, ",")...),
		port + "/RemotePort": firewallParts(strings.Split(s.RemotePorts, ",")...), port + "/IcmpType": firewallParts("Any"), port + "/DynamicTransport": {"N:0"},
		// The omitted NetSecurity InterfaceType means Any. The .107 legacy
		// readback projects it as CIM 0. Do not import a separate netfw All
		// bitmask as this provider default. Exact alias remains mandatory.
		"MSFT_NetInterfaceFilter/InterfaceAlias": firewallParts(s.Alias), "MSFT_NetInterfaceTypeFilter/InterfaceType": {"N:0"},
		"MSFT_NetServiceFilter/ServiceName":                 firewallParts(s.Service),
		"MSFT_NetNetworkLayerSecurityFilter/Authentication": {"N:0"}, "MSFT_NetNetworkLayerSecurityFilter/Encryption": {"N:0"},
		"MSFT_NetNetworkLayerSecurityFilter/OverrideBlockRules": {"B:false"},
		"MSFT_NetNetworkLayerSecurityFilter/LocalUsers":         firewallParts(""), "MSFT_NetNetworkLayerSecurityFilter/RemoteUsers": firewallParts(""),
		"MSFT_NetNetworkLayerSecurityFilter/RemoteMachines": firewallParts(""),
		"/RemoteDynamicKeywordAddresses":                    {}, "/dynamic_source": firewallParts("RULE"),
	}
	if s.Protocol == 1 {
		want[port+"/IcmpType"] = firewallParts("8")
	}
	return want
}

// Explicit absence representations are bounded per property, never inferred
// from unreadable/missing data. Fingerprints preserve NULL versus empty and
// the provider location, so even an allowed projection change rejects reuse.
func firewallDefaultMatches(key string, got, expected []string, protocol int32, all firewallConstraints) bool {
	switch key {
	case "/Platforms", "/RemoteDynamicKeywordAddresses":
		return len(expected) == 0 && (len(got) == 0 || slices.Equal(got, []string{"NULL"}))
	case "/Owner", "/PackageFamilyName", "/PolicyAppId", "MSFT_NetApplicationFilter/Package":
		return slices.Equal(expected, []string{"S:"}) && (slices.Equal(got, []string{"S:"}) || slices.Equal(got, []string{"NULL"}))
	case "MSFT_NetProtocolPortFilter/LocalPort":
		return (protocol == 1 || protocol == 58) && slices.Equal(expected, []string{"S:Any"}) && slices.Equal(got, []string{"NULL"})
	case "MSFT_NetProtocolPortFilter/RemotePort":
		return (protocol == 1 || protocol == 58 || protocol == 6 || protocol == 17) && slices.Equal(expected, []string{"S:Any"}) && slices.Equal(got, []string{"NULL"})
	case "MSFT_NetServiceFilter/ServiceName":
		return slices.Equal(expected, []string{"S:Any"}) && slices.Equal(got, []string{"NULL"})
	case "MSFT_NetNetworkLayerSecurityFilter/LocalUsers", "MSFT_NetNetworkLayerSecurityFilter/RemoteUsers", "MSFT_NetNetworkLayerSecurityFilter/RemoteMachines":
		return slices.Equal(expected, []string{"S:"}) && slices.Equal(got, []string{"NULL"}) &&
			slices.Equal(all["/Action"], []string{"N:2"}) &&
			slices.Equal(all["MSFT_NetNetworkLayerSecurityFilter/Authentication"], []string{"N:0"}) &&
			slices.Equal(all["MSFT_NetNetworkLayerSecurityFilter/Encryption"], []string{"N:0"}) &&
			slices.Equal(all["MSFT_NetNetworkLayerSecurityFilter/OverrideBlockRules"], []string{"B:false"})
	case "MSFT_NetProtocolPortFilter/IcmpType":
		return protocol != 1 && protocol != 58 && slices.Equal(expected, []string{"S:Any"}) && (len(got) == 0 || slices.Equal(got, []string{"NULL"}) || slices.Equal(got, []string{"S:Any"}))
	case "/dynamic_source":
		return slices.Equal(expected, []string{"S:RULE"}) && (slices.Equal(got, []string{"S:RULE"}) || slices.Equal(got, []string{"S:ADDRESS"}))
	}
	return false
}

// The only current ICMP creation factory is IPv4 echo type 8. Microsoft marks
// LocalPort/RemotePort applicable only to TCP/UDP. Do not write ignored ports
// for ICMP, infer an IPv6 echo type, or admit unknown protocol factory plans.
func nativeFirewallPortWriteFields(s nativeRuleSpec) ([]string, error) {
	switch s.Protocol {
	case 1:
		if s.Ports != "Any" || s.RemotePorts != "Any" || s.ICMP != "8" {
			return nil, errors.New("USB_NATIVE_FIREWALL_ICMP_PLAN_UNSUPPORTED")
		}
		return []string{"Protocol", "IcmpType"}, nil
	case 6, 17:
		if s.ICMP != "" {
			return nil, errors.New("USB_NATIVE_FIREWALL_PROTOCOL_PLAN_UNSUPPORTED")
		}
		return []string{"Protocol", "LocalPort", "RemotePort"}, nil
	}
	return nil, errors.New("USB_NATIVE_FIREWALL_PROTOCOL_PLAN_UNSUPPORTED")
}

func verifyFirewallConstraints(got firewallConstraints, s nativeRuleSpec, enabled int32) error {
	want := expectedFirewallConstraints(s, enabled)
	if len(got) != len(want) {
		return errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_INCOMPLETE")
	}
	for key, expected := range want {
		actual, exists := got[key]
		if !exists {
			return errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_INCOMPLETE")
		}
		if !slices.Equal(actual, expected) && !firewallDefaultMatches(key, actual, expected, s.Protocol, got) {
			return errors.New("USB_NATIVE_FIREWALL_SCOPE_CHANGED")
		}
	}
	return nil
}

func firewallFingerprint(got firewallConstraints) (string, error) {
	b, err := json.Marshal(got)
	if err != nil || len(b) > 16384 {
		return "", errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_LIMIT")
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}

// This proof has no mutation callback. Neither a cold cache nor a mismatch
// authorizes removal/replacement. Each reader must requery one exact rule and
// all one-to-one filters; the NIC proof runs before, between and after reads.
func verifyNativeRuleReuse(s nativeRuleSpec, baseline string, read func() (firewallConstraints, error), verifyNIC func() error) (string, error) {
	return verifyNativeRuleReadbacks(s, 1, baseline, read, verifyNIC)
}

func verifyNativeRuleReadbacks(s nativeRuleSpec, enabled int32, baseline string, read func() (firewallConstraints, error), verifyNIC func() error) (string, error) {
	if enabled != 1 && enabled != 2 {
		return "", errors.New("USB_NATIVE_FIREWALL_ENABLED_STATE_UNKNOWN")
	}
	if read == nil || verifyNIC == nil {
		return "", errors.New("USB_NATIVE_FIREWALL_PROOF_REQUIRED")
	}
	var first string
	for i := 0; i < 2; i++ {
		if err := verifyNIC(); err != nil {
			return "", err
		}
		got, err := read()
		if err != nil {
			return "", err
		}
		if err = verifyFirewallConstraints(got, s, enabled); err != nil {
			return "", err
		}
		hash, err := firewallFingerprint(got)
		if err != nil {
			return "", err
		}
		if (baseline != "" && hash != baseline) || (i == 1 && hash != first) {
			return "", errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_CHANGED")
		}
		first = hash
	}
	if err := verifyNIC(); err != nil {
		return "", err
	}
	return first, nil
}

// A cleanup proof accepts only a complete enabled or complete disabled rule.
// A marker, partial creation, unknown Enabled value, or changed projection
// never authorizes deletion. This helper has no mutation callback.
func verifyNativeRuleCleanup(s nativeRuleSpec, baseline string, read func() (firewallConstraints, error), verifyOwner func() error) (string, error) {
	if read == nil || verifyOwner == nil {
		return "", errors.New("USB_NATIVE_FIREWALL_PROOF_REQUIRED")
	}
	var enabled int32
	first := true
	return verifyNativeRuleCleanupReadbacks(baseline, func() (firewallConstraints, error) {
		got, err := read()
		if err != nil {
			return nil, err
		}
		value := got["/Enabled"]
		if first {
			first = false
			if slices.Equal(value, []string{"N:1"}) {
				enabled = 1
			} else if slices.Equal(value, []string{"N:2"}) {
				enabled = 2
			} else {
				return nil, errors.New("USB_NATIVE_FIREWALL_ENABLED_STATE_UNKNOWN")
			}
		}
		if err = verifyFirewallConstraints(got, s, enabled); err != nil {
			return nil, err
		}
		return got, nil
	}, verifyOwner)
}

func verifyNativeRuleCleanupReadbacks(baseline string, read func() (firewallConstraints, error), verifyOwner func() error) (string, error) {
	var first string
	for i := 0; i < 2; i++ {
		if err := verifyOwner(); err != nil {
			return "", err
		}
		got, err := read()
		if err != nil {
			return "", err
		}
		hash, err := firewallFingerprint(got)
		if err != nil {
			return "", err
		}
		if (baseline != "" && hash != baseline) || (i == 1 && hash != first) {
			return "", errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_CHANGED")
		}
		first = hash
	}
	if err := verifyOwner(); err != nil {
		return "", err
	}
	return first, nil
}

// All fixed rules are fully authorized before the first mutation. Missing is
// represented only by the reader's explicit nil result; read errors are never
// absence. The private remover must re-read its exact provider object against
// the supplied fingerprint immediately before deletion and verify absence.
func executeNativeRuleCleanup(specs []nativeRuleSpec, read func(nativeRuleSpec) (firewallConstraints, error), verifyOwner func() error, remove func(nativeRuleSpec, string) error) error {
	if read == nil || verifyOwner == nil || remove == nil {
		return errors.New("USB_NATIVE_FIREWALL_PROOF_REQUIRED")
	}
	proofs := make(map[string]string, len(specs))
	for _, spec := range specs {
		if _, exists := proofs[spec.Name]; exists {
			return errors.New("USB_NATIVE_SESSION_RULE_SCOPE_INVALID")
		}
		if err := verifyOwner(); err != nil {
			return err
		}
		got, err := read(spec)
		if err != nil {
			return err
		}
		if got == nil {
			proofs[spec.Name] = ""
			continue
		}
		hash, err := verifyNativeRuleCleanup(spec, "", func() (firewallConstraints, error) { return read(spec) }, verifyOwner)
		if err != nil {
			return err
		}
		proofs[spec.Name] = hash
	}
	if err := verifyOwner(); err != nil {
		return err
	}
	for _, spec := range specs {
		baseline := proofs[spec.Name]
		if baseline == "" {
			continue
		}
		if _, err := verifyNativeRuleCleanup(spec, baseline, func() (firewallConstraints, error) { return read(spec) }, verifyOwner); err != nil {
			return err
		}
		if err := remove(spec, baseline); err != nil {
			return err
		}
	}
	return verifyOwner()
}
