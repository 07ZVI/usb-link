package netconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/usbaddress"
)

const residentGroup = "USB-Link-Resident-Network-v1"
const residentMarker = "USB Link fixed USB network scope / v1"
const residentLedgerLimit = 131072

type residentRuleObservation struct {
	Present     bool
	Constraints firewallConstraints
}
type residentLedger struct {
	Version               int
	Role, GUID, Phase, ID string
	Specs                 []nativeRuleSpec
	Previous              []nativeRuleSpec
	Before                []residentRuleObservation
}

func residentSpecs(role, guid, alias, exe string) ([]nativeRuleSpec, error) {
	if !guidPattern.MatchString(guid) || alias == "" || len(alias) > 128 || strings.ContainsAny(alias, "\x00\r\n*?[]") || strings.EqualFold(alias, "Any") {
		return nil, errors.New("USB_RESIDENT_SCOPE_INVALID")
	}
	base := nativeRuleSpec{Group: residentGroup, Description: residentMarker, Display: "USB Link USB network", Alias: alias, Program: "Any", Service: "Any", Local: "10.6.9.1", Remote: "10.6.9.2", RemotePorts: "Any"}
	var out []nativeRuleSpec
	add := func(name, ports string, protocol int32) {
		s := base
		s.Name = name
		s.Ports = ports
		s.Protocol = protocol
		if protocol == 1 {
			s.ICMP = "8"
			s.Ports = "Any"
		}
		out = append(out, s)
	}
	core := func(name, peer, ports, program, service string, protocol int32, local, remotePorts string) {
		s := base
		s.Group = serviceGroup
		s.Description = serviceMarker
		s.Display = "USB Link USB services"
		s.Name = name
		s.Remote = peer
		s.Local = local
		s.Ports = ports
		s.Program = program
		s.Service = service
		s.Protocol = protocol
		s.RemotePorts = remotePorts
		out = append(out, s)
	}
	smb := func(peer string) {
		core("USB-Link-Native-SMB-"+guid+"-"+strings.ReplaceAll(peer, ".", "-"), peer, "445", "System", "LanmanServer", 6, "10.6.9.1", "Any")
	}
	switch role {
	case "mac":
		if !strings.EqualFold(guid, "{A4611646-E050-4D25-B83E-633A5598F302}") || alias != "USB Link" {
			return nil, errors.New("USB_RESIDENT_SCOPE_INVALID")
		}
		add("USB-Link-Resident-Mac-ICMP-v1", "Any", 1)
		add("USB-Link-Resident-Mac-BENCH-v1", securitypolicy.Ports(securitypolicy.NativeBenchmark, "TCP"), 6)
		add("USB-Link-Resident-Mac-SUN-TCP-v1", securitypolicy.InboundPorts("mac", "TCP"), 6)
		add("USB-Link-Resident-Mac-SUN-UDP-v1", securitypolicy.InboundPorts("mac", "UDP"), 17)
		add("USB-Link-Resident-Mac-FILES-v1", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP"), 6)
	case "ipad":
		base.Remote = "10.6.9.3"
		base.Local = "Any"
		base.Remote = "Any"
		base.RemotePorts = "68"
		add("USB-Link-Resident-iPad-DHCP-v1", "67", 17)
		base.RemotePorts = "Any"
		add("USB-Link-Resident-iPad-MDNS-v1", "5353", 17)
		base.Local = "10.6.9.1"
		base.Remote = "10.6.9.3"
		add("USB-Link-Resident-iPad-TCP-v1", securitypolicy.InboundPorts("ipad", "TCP"), 6)
		add("USB-Link-Resident-iPad-UDP-v1", securitypolicy.InboundPorts("ipad", "UDP"), 17)
	case "host", "core_mac", "core_ipad":
		if !validCoreExecutable(exe) {
			return nil, errors.New("USB_RESIDENT_SOURCE_INVALID")
		}
		if role == "host" && !strings.EqualFold(guid, usbaddress.HostGUID) {
			return nil, errors.New("USB_RESIDENT_SCOPE_INVALID")
		}
		if role == "core_mac" && !strings.EqualFold(guid, "{A4611646-E050-4D25-B83E-633A5598F302}") {
			return nil, errors.New("USB_RESIDENT_SCOPE_INVALID")
		}
		if role != "core_ipad" {
			name := "USB-Link-Core-Mac-v1"
			if role == "host" {
				name = "USB-Link-Core-Host-Mac-v1"
			}
			core(name, "10.6.9.2", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")+",47775", exe, "Any", 6, "10.6.9.1", "Any")
			smb("10.6.9.2")
		}
		if role != "core_mac" {
			name := "USB-Link-Core-iPad-v1"
			if role == "host" {
				name = "USB-Link-Core-Host-iPad-v1"
			}
			core(name, "10.6.9.3", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP"), exe, "Any", 6, "10.6.9.1", "Any")
			smb("10.6.9.3")
		}
		if role == "core_ipad" {
			core("USB-Link-Core-DHCP-v1", "Any", "67", exe, "Any", 17, "Any", "68")
			core("USB-Link-Core-MDNS-v1", "Any", "5353", exe, "Any", 17, "Any", "Any")
		}
	default:
		return nil, errors.New("USB_RESIDENT_ROLE_INVALID")
	}
	return out, nil
}

// These anchors cannot drift even with a protected receipt. Defaults/security
// may be precisely repaired, but a changed peer, program, port or interface is
// potentially another principal's rule and never becomes deletion authority.
var residentAnchors = []string{"/InstanceID", "/RuleGroup", "/Description", "MSFT_NetApplicationFilter/AppPath", "MSFT_NetServiceFilter/ServiceName", "MSFT_NetInterfaceFilter/InterfaceAlias", "MSFT_NetAddressFilter/LocalAddress", "MSFT_NetAddressFilter/RemoteAddress", "MSFT_NetProtocolPortFilter/Protocol", "MSFT_NetProtocolPortFilter/LocalPort", "MSFT_NetProtocolPortFilter/RemotePort", "MSFT_NetProtocolPortFilter/IcmpType"}

func residentRepairAllowed(got firewallConstraints, old nativeRuleSpec) error {
	got = residentConstraintProjection(got, old)
	want := expectedFirewallConstraints(old, 1)
	if len(got) != len(want) {
		return errors.New("USB_RESIDENT_CONSTRAINT_INCOMPLETE")
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			return residentConstraintFailure(key, errors.New("USB_RESIDENT_CONSTRAINT_INCOMPLETE"))
		}
	}
	if e := residentConstraintTypes(got); e != nil {
		return e
	}
	for _, key := range residentAnchors {
		a := got[key]
		w := want[key]
		if !slices.Equal(a, w) && !firewallDefaultMatches(key, a, w, old.Protocol, got) {
			return residentConstraintFailure(key, errors.New("USB_RESIDENT_FOREIGN_SCOPE"))
		}
	}
	return nil
}
func residentConstraintTypes(c firewallConstraints) error {
	nullable := map[string]bool{"IcmpType": true, "Platforms": true, "Owner": true, "PackageFamilyName": true, "PolicyAppId": true, "Package": true, "RemoteDynamicKeywordAddresses": true, "LocalUsers": true, "RemoteUsers": true, "RemoteMachines": true, "LocalPort": true, "RemotePort": true, "ServiceName": true}
	arrays := map[string]bool{"Platforms": true, "LocalAddress": true, "RemoteAddress": true, "LocalPort": true, "RemotePort": true, "IcmpType": true, "InterfaceAlias": true, "RemoteDynamicKeywordAddresses": true}
	numeric := map[string][]uint64{"Enabled": {1, 2}, "Direction": {1, 2}, "Action": {2, 3, 4}, "Profiles": {0, 1, 2, 3, 4, 5, 6, 7}, "EdgeTraversalPolicy": {0, 1, 2, 3}, "DynamicTransport": {0, 1, 2, 4, 8, 16}, "InterfaceType": {0, 1, 2, 4}, "Authentication": {0, 1, 2}, "Encryption": {0, 1, 2}}
	for key, parts := range c {
		field := key[strings.LastIndex(key, "/")+1:]
		bad := func() error {
			return residentConstraintFailure(key, errors.New("USB_RESIDENT_CONSTRAINT_TYPE_UNKNOWN"))
		}
		if len(parts) > 64 {
			return bad()
		}
		if nullable[field] && slices.Equal(parts, []string{"NULL"}) {
			continue
		}
		if field == "Protocol" {
			if len(parts) != 1 || !strings.HasPrefix(parts[0], "N:") {
				return bad()
			}
			n, e := strconv.ParseUint(parts[0][2:], 10, 8)
			if e != nil || fmt.Sprint("N:", n) != parts[0] {
				return bad()
			}
			continue
		}
		if values, ok := numeric[field]; ok {
			if len(parts) != 1 || !strings.HasPrefix(parts[0], "N:") {
				return bad()
			}
			n, e := strconv.ParseUint(parts[0][2:], 10, 32)
			if e != nil || !slices.Contains(values, n) || fmt.Sprint("N:", n) != parts[0] {
				return bad()
			}
			continue
		}
		if field == "LooseSourceMapping" || field == "LocalOnlyMapping" || field == "OverrideBlockRules" {
			if !slices.Equal(parts, []string{"B:true"}) && !slices.Equal(parts, []string{"B:false"}) {
				return bad()
			}
			continue
		}
		if !arrays[field] && len(parts) != 1 {
			return bad()
		}
		for i, v := range parts {
			if !strings.HasPrefix(v, "S:") || len(v) > 1026 || strings.ContainsRune(v, 0) || (i > 0 && parts[i-1] >= v) {
				return bad()
			}
		}
		if field == "dynamic_source" && !slices.Equal(parts, []string{"S:RULE"}) && !slices.Equal(parts, []string{"S:ADDRESS"}) {
			return bad()
		}
	}
	return nil
}

// First adoption across a versioned executable is limited to one installed
// previous source and a complete old compiled scope. The callback must verify
// that exact ProgramFiles release/ownership/hash; a group marker is insufficient.
func residentRecognizeLegacySource(specs []nativeRuleSpec, obs []residentRuleObservation, role, guid, alias string, verify func(string) error) ([]nativeRuleSpec, error) {
	if role != "host" && role != "core_mac" && role != "core_ipad" {
		return nil, nil
	}
	if len(specs) != len(obs) || verify == nil {
		return nil, errors.New("USB_RESIDENT_LEGACY_SOURCE_REQUIRED")
	}
	program := ""
	for i, o := range obs {
		if !o.Present || verifyFirewallConstraints(o.Constraints, specs[i], 1) == nil {
			continue
		}
		v := o.Constraints["MSFT_NetApplicationFilter/AppPath"]
		if len(v) != 1 || !strings.HasPrefix(v[0], "S:") {
			return nil, errors.New("USB_RESIDENT_UNKNOWN_RULE")
		}
		candidate := strings.TrimPrefix(v[0], "S:")
		if candidate == specs[i].Program || !validCoreExecutable(candidate) || (program != "" && program != candidate) {
			return nil, errors.New("USB_RESIDENT_UNKNOWN_RULE")
		}
		program = candidate
	}
	if program == "" {
		return nil, nil
	}
	old, e := residentSpecs(role, guid, alias, program)
	if e != nil {
		return nil, e
	}
	for i, o := range obs {
		if o.Present && verifyFirewallConstraints(o.Constraints, specs[i], 1) != nil && verifyFirewallConstraints(o.Constraints, old[i], 1) != nil {
			return nil, errors.New("USB_RESIDENT_UNKNOWN_RULE")
		}
	}
	if e = verify(program); e != nil {
		return nil, e
	}
	return old, nil
}

func residentLedgerValid(v residentLedger) error {
	if v.Version != 1 || !idPattern.MatchString(v.ID) || (v.Phase != "prepared" && v.Phase != "complete" && v.Phase != "removing") || len(v.Specs) == 0 || len(v.Specs) > 5 || len(v.Before) != len(v.Specs) {
		return errors.New("USB_RESIDENT_LEDGER_INVALID")
	}
	compiled, e := residentSpecs(v.Role, v.GUID, v.Specs[0].Alias, v.Specs[0].Program)
	if e != nil || !reflect.DeepEqual(compiled, v.Specs) {
		return errors.New("USB_RESIDENT_LEDGER_SCOPE_INVALID")
	}
	prior := v.Specs
	if len(v.Previous) != 0 {
		old, e := residentSpecs(v.Role, v.GUID, v.Previous[0].Alias, v.Previous[0].Program)
		if e != nil || !reflect.DeepEqual(old, v.Previous) || len(old) != len(v.Specs) || v.Phase == "complete" {
			return errors.New("USB_RESIDENT_LEDGER_SCOPE_INVALID")
		}
		prior = old
	}
	for i, b := range v.Before {
		if !b.Present {
			if b.Constraints != nil || v.Phase == "complete" {
				return errors.New("USB_RESIDENT_LEDGER_INVALID")
			}
			continue
		}
		if _, e := firewallFingerprint(b.Constraints); e != nil {
			return e
		}
		if e := residentRepairAllowed(b.Constraints, prior[i]); e != nil {
			if v.Phase == "complete" || residentRepairAllowed(b.Constraints, v.Specs[i]) != nil {
				return e
			}
		}
		if v.Phase == "complete" {
			if e := verifyResidentFirewallConstraints(b.Constraints, v.Specs[i], 1); e != nil {
				return e
			}
		}
	}
	return nil
}

// Reject duplicate fields recursively; protected bytes are still parsed as an
// exact schema, rather than relying on encoding/json's last-key-wins behavior.
func residentJSONUnique(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[strings.ToLower(s)] {
					return errors.New("duplicate")
				}
				seen[strings.ToLower(s)] = true
				if e = residentJSONUnique(d); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case '[':
			for d.More() {
				if e = residentJSONUnique(d); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		default:
			return errors.New("delimiter")
		}
	}
	return nil
}
func residentExactObject(b []byte, t reflect.Type) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != t.NumField() {
		return errors.New("USB_RESIDENT_LEDGER_INVALID")
	}
	for i := 0; i < t.NumField(); i++ {
		if _, ok := fields[t.Field(i).Name]; !ok {
			return errors.New("USB_RESIDENT_LEDGER_INVALID")
		}
	}
	return nil
}
func residentExactSchema(b []byte) error {
	if e := residentExactObject(b, reflect.TypeOf(residentLedger{})); e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for _, name := range []string{"Specs", "Previous"} {
		var rows []json.RawMessage
		if json.Unmarshal(fields[name], &rows) != nil {
			return errors.New("USB_RESIDENT_LEDGER_INVALID")
		}
		for _, row := range rows {
			if e := residentExactObject(row, reflect.TypeOf(nativeRuleSpec{})); e != nil {
				return e
			}
		}
	}
	var rows []json.RawMessage
	if json.Unmarshal(fields["Before"], &rows) != nil {
		return errors.New("USB_RESIDENT_LEDGER_INVALID")
	}
	for _, row := range rows {
		if e := residentExactObject(row, reflect.TypeOf(residentRuleObservation{})); e != nil {
			return e
		}
	}
	return nil
}

func decodeResidentLedger(b []byte) (residentLedger, error) {
	var v residentLedger
	if len(b) == 0 || len(b) > residentLedgerLimit {
		return v, errors.New("USB_RESIDENT_LEDGER_LIMIT")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	if e := residentJSONUnique(d); e != nil {
		return v, errors.New("USB_RESIDENT_LEDGER_INVALID")
	}
	if _, e := d.Token(); e != io.EOF {
		return v, errors.New("USB_RESIDENT_LEDGER_INVALID")
	}
	if e := residentExactSchema(b); e != nil {
		return v, e
	}
	d = json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return v, errors.New("USB_RESIDENT_LEDGER_INVALID")
	}
	return v, residentLedgerValid(v)
}
func residentLeaf(role string) (string, error) {
	switch role {
	case "host", "mac", "ipad", "core_mac", "core_ipad":
		return fmt.Sprintf("resident-firewall-%s-v1.json", role), nil
	}
	return "", errors.New("USB_RESIDENT_ROLE_INVALID")
}
