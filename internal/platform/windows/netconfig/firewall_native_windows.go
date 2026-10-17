//go:build windows && amd64

package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"suhang/usbnet/internal/platform/windows/wincom"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/usbaddress"
	"sync"
)

const wmiLocatorCLSID = "{76A64158-CB41-11D1-8B02-00600806D9B6}"

var nativeRuleCache = struct {
	sync.Mutex
	hashes map[string]string
}{hashes: map[string]string{}}

func comObject(value wincom.Value, err error) (*wincom.Dispatch, error) {
	defer value.Clear()
	if err != nil {
		return nil, err
	}
	return value.Dispatch()
}
func comString(d *wincom.Dispatch, member string) (string, error) {
	v, e := d.Get(member)
	defer v.Clear()
	if e != nil {
		return "", e
	}
	return v.String()
}
func comInt(d *wincom.Dispatch, member string) (int32, error) {
	v, e := d.Get(member)
	defer v.Clear()
	if e != nil {
		return 0, e
	}
	return v.Int()
}
func enumerateCOM(d *wincom.Dispatch, max int, fn func(*wincom.Dispatch) error) error {
	v, e := d.Get("_NewEnum")
	defer v.Clear()
	if e != nil {
		return e
	}
	return wincom.Enumerate(v, max, func(item wincom.Value) error {
		d, e := item.Dispatch()
		if e != nil {
			return e
		}
		defer d.Close()
		return fn(d)
	})
}
func withFirewall(ctx context.Context, fn func(*wincom.Dispatch) error) error {
	if ctx == nil {
		return errors.New("USB_NATIVE_FIREWALL_CONTEXT_REQUIRED")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return wincom.WithApartment(func() error {
		locator, e := wincom.Create(wmiLocatorCLSID)
		if e != nil {
			return e
		}
		defer locator.Close()
		svc, e := comObject(locator.Call("ConnectServer", wincom.String("."), wincom.String(`root\standardcimv2`)))
		if e != nil {
			return e
		}
		defer svc.Close()
		return fn(svc)
	})
}
func cimProperty(d *wincom.Dispatch, name string) (wincom.Value, error) {
	p, e := comObject(d.Get("Properties_"))
	if e != nil {
		return wincom.Empty(), e
	}
	defer p.Close()
	property, e := comObject(p.Call("Item", wincom.String(name)))
	if e != nil {
		return wincom.Empty(), e
	}
	defer property.Close()
	return property.Get("Value")
}
func cimSet(d *wincom.Dispatch, name string, value wincom.Value) error {
	p, e := comObject(d.Get("Properties_"))
	if e != nil {
		return e
	}
	defer p.Close()
	property, e := comObject(p.Call("Item", wincom.String(name)))
	if e != nil {
		return e
	}
	defer property.Close()
	return property.Put("Value", value)
}
func cimString(d *wincom.Dispatch, name string) (string, error) {
	v, e := cimProperty(d, name)
	defer v.Clear()
	if e != nil {
		return "", e
	}
	return v.String()
}
func cimInt(d *wincom.Dispatch, name string) (int32, error) {
	v, e := cimProperty(d, name)
	defer v.Clear()
	if e != nil {
		return 0, e
	}
	return v.Int()
}
func cimPut(d *wincom.Dispatch, flags int32) error {
	v, e := d.Call("Put_", wincom.Int(flags))
	v.Clear()
	return e
}
func cimDelete(d *wincom.Dispatch) error {
	v, e := d.Call("Delete_", wincom.Int(0))
	v.Clear()
	return e
}
func matchingRule(svc *wincom.Dispatch, name string) (*wincom.Dispatch, error) {
	// Selectors are internal fixed names or generated lower-case ownership tokens.
	if len(name) > 160 || strings.ContainsAny(name, "'\r\n\x00\\") {
		return nil, errors.New("USB_NATIVE_FIREWALL_NAME_INVALID")
	}
	rows, e := comObject(svc.Call("ExecQuery", wincom.String("SELECT * FROM MSFT_NetFirewallRule WHERE InstanceID='"+name+"'"), wincom.String("WQL"), wincom.Int(0)))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	count, e := comInt(rows, "Count")
	if e != nil || count < 0 || count > 1 {
		return nil, errors.New("USB_NATIVE_FIREWALL_ENUMERATION_OR_AMBIGUITY")
	}
	if count == 0 {
		return nil, nil
	}
	var result *wincom.Dispatch
	e = enumerateCOM(rows, 2, func(r *wincom.Dispatch) error {
		if result != nil {
			return errors.New("USB_NATIVE_FIREWALL_ENUMERATION_OR_AMBIGUITY")
		}
		n, e := cimString(r, "InstanceID")
		if e != nil || n != name {
			return errors.New("USB_NATIVE_FIREWALL_NAME_CHANGED")
		}
		v := wincom.Object(r)
		result, e = v.Dispatch()
		return e
	})
	if e != nil {
		if result != nil {
			result.Close()
		}
		return nil, e
	}
	if result == nil {
		return nil, errors.New("USB_NATIVE_FIREWALL_ENUMERATION_INCOMPLETE")
	}
	return result, nil
}

func cimRelated(rule *wincom.Dispatch, class string) (*wincom.Dispatch, error) {
	rows, e := comObject(rule.Call("Associators_", wincom.String(""), wincom.String(class)))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	count, e := comInt(rows, "Count")
	if e != nil || !firewallFilterCountProven(count) {
		return nil, errors.New("USB_NATIVE_FIREWALL_FILTER_UNPROVEN")
	}
	var result *wincom.Dispatch
	e = enumerateCOM(rows, 2, func(d *wincom.Dispatch) error {
		if result != nil {
			return errors.New("USB_NATIVE_FIREWALL_FILTER_AMBIGUOUS")
		}
		v := wincom.Object(d)
		var e error
		result, e = v.Dispatch()
		return e
	})
	if e != nil {
		if result != nil {
			result.Close()
		}
		return nil, e
	}
	if result == nil {
		return nil, errors.New("USB_NATIVE_FIREWALL_FILTER_UNPROVEN")
	}
	return result, nil
}
func constraintValues(v wincom.Value, field string) ([]string, error) {
	if field == "Protocol" {
		text, err := v.String()
		if err != nil {
			return nil, errors.New("USB_NATIVE_FIREWALL_PROTOCOL_TYPE_UNKNOWN")
		}
		switch text {
		case "ICMPv4":
			text = "1"
		case "TCP":
			text = "6"
		case "UDP":
			text = "17"
		case "ICMPv6":
			text = "58"
		}
		n, err := strconv.ParseUint(text, 10, 8)
		if err != nil {
			return nil, errors.New("USB_NATIVE_FIREWALL_PROTOCOL_UNKNOWN")
		}
		return []string{fmt.Sprint("N:", n)}, nil
	}

	switch field {
	case "LooseSourceMapping", "LocalOnlyMapping", "OverrideBlockRules":
		if _, err := v.Bool(); err != nil {
			return nil, errors.New("USB_NATIVE_FIREWALL_BOOLEAN_UNKNOWN")
		}
	case "Enabled", "Direction", "Action", "Profiles", "EdgeTraversalPolicy", "DynamicTransport", "InterfaceType", "Authentication", "Encryption":
		number, err := v.UInt()
		if err != nil {
			return nil, errors.New("USB_NATIVE_FIREWALL_ENUM_UNKNOWN")
		}
		known := false
		switch field {
		case "Enabled", "Direction":
			known = number == 1 || number == 2
		case "Action":
			known = number == 2 || number == 3 || number == 4
		case "Profiles":
			known = number <= 7
		case "EdgeTraversalPolicy":
			known = number <= 3
		case "DynamicTransport":
			known = number == 0 || number == 1 || number == 2 || number == 4 || number == 8 || number == 16
		case "InterfaceType":
			known = number == 0 || number == 1 || number == 2 || number == 4
		case "Authentication", "Encryption":
			known = number <= 2
		}
		if !known {
			return nil, errors.New("USB_NATIVE_FIREWALL_ENUM_UNKNOWN")
		}
	}
	nullable := field == "IcmpType" || field == "Platforms" || field == "Owner" || field == "PackageFamilyName" || field == "PolicyAppId" || field == "Package" || field == "RemoteDynamicKeywordAddresses" || field == "LocalUsers" || field == "RemoteUsers" || field == "RemoteMachines" || field == "LocalPort" || field == "RemotePort" || field == "ServiceName"
	if v.IsNull() {
		if nullable {
			return []string{"NULL"}, nil
		}
		return nil, errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_NULL")
	}
	isArray := field == "Platforms" || field == "LocalAddress" || field == "RemoteAddress" || field == "LocalPort" || field == "RemotePort" || field == "IcmpType" || field == "InterfaceAlias" || field == "RemoteDynamicKeywordAddresses"
	if isArray {
		values, e := v.Strings(64)
		if e != nil {
			return nil, errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_TYPE_UNKNOWN")
		}
		parts := make([]string, 0, len(values))
		for _, item := range values {
			if len(item) > 1024 || strings.ContainsRune(item, 0) {
				return nil, errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_LIMIT")
			}
			parts = append(parts, "S:"+item)
		}
		sort.Strings(parts)
		for i := 1; i < len(parts); i++ {
			if parts[i] == parts[i-1] {
				return nil, errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_DUPLICATE")
			}
		}
		return parts, nil
	}
	switch field {
	case "LooseSourceMapping", "LocalOnlyMapping", "OverrideBlockRules":
		b, _ := v.Bool() // The exact type was checked above.
		return []string{fmt.Sprint("B:", b)}, nil
	case "Enabled", "Direction", "Action", "Profiles", "EdgeTraversalPolicy", "DynamicTransport", "InterfaceType", "Authentication", "Encryption":
		n, _ := v.UInt()
		return []string{fmt.Sprint("N:", n)}, nil
	}
	value, e := v.String()
	if e != nil {
		return nil, errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_TYPE_UNKNOWN")
	}
	if len(value) > 1024 || strings.ContainsRune(value, 0) {
		return nil, errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_LIMIT")
	}
	return []string{"S:" + value}, nil
}
func readFirewallConstraints(rule *wincom.Dispatch) (firewallConstraints, error) {
	return readFirewallConstraintsMode(rule, false)
}

func readFirewallConstraintValue(v wincom.Value, class, field string, residentMacAppPathNull bool) ([]string, error) {
	if residentMacAppPathNull && class == "MSFT_NetApplicationFilter" && field == "AppPath" && v.IsNull() {
		return []string{"NULL"}, nil
	}
	return constraintValues(v, field)
}

// Only residentReadRules may request the private compiled-Mac compatibility.
// Generic native setup, reuse, cleanup and legacy migration remain strict.
func readFirewallConstraintsMode(rule *wincom.Dispatch, residentMacAppPathNull bool) (firewallConstraints, error) {
	snapshot := firewallConstraints{}
	var addr *wincom.Dispatch
	defer func() {
		if addr != nil {
			addr.Close()
		}
	}()
	for i, g := range firewallGroups {
		d := rule
		if g.class != "" {
			var e error
			d, e = cimRelated(rule, g.class)
			if e != nil {
				return nil, firewallReadFailure(g.class, "_association", e)
			}
			if i == 2 {
				addr = d
			} else {
				defer d.Close()
			}
		}
		for _, field := range g.fields {
			v, e := cimProperty(d, field)
			if e != nil {
				return nil, firewallReadFailure(g.class, field, errors.Join(errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_UNKNOWN"), e))
			}
			parts, e := readFirewallConstraintValue(v, g.class, field, residentMacAppPathNull)
			v.Clear()
			if e != nil {
				return nil, firewallReadFailure(g.class, field, e)
			}
			snapshot[firewallField(g.class, field)] = parts
		}
	}
	rv, re := cimProperty(rule, "RemoteDynamicKeywordAddresses")
	av, ae := cimProperty(addr, "RemoteDynamicKeywordAddresses")
	defer rv.Clear()
	defer av.Clear()
	if (re == nil) == (ae == nil) {
		return nil, firewallReadFailure("", "RemoteDynamicKeywordAddresses", errors.New("USB_NATIVE_FIREWALL_DYNAMIC_CONSTRAINT_UNKNOWN"))
	}
	dynamic, where := rv, "RULE"
	if ae == nil {
		dynamic, where = av, "ADDRESS"
	}
	parts, e := constraintValues(dynamic, "RemoteDynamicKeywordAddresses")
	if e != nil {
		class := ""
		if ae == nil {
			class = "MSFT_NetAddressFilter"
		}
		return nil, firewallReadFailure(class, "RemoteDynamicKeywordAddresses", e)
	}
	snapshot["/RemoteDynamicKeywordAddresses"] = parts
	snapshot["/dynamic_source"] = firewallParts(where)
	return snapshot, nil
}
func firewallConstraintSnapshot(rule *wincom.Dispatch) (string, error) {
	got, err := readFirewallConstraints(rule)
	if err != nil {
		return "", err
	}
	return firewallFingerprint(got)
}
func firewallOwns(rule *wincom.Dispatch, s nativeRuleSpec) error {
	g, e := cimString(rule, "RuleGroup")
	if e != nil || g != s.Group {
		return errors.New("USB_NATIVE_FIREWALL_OWNERSHIP_CHANGED")
	}
	d, e := cimString(rule, "Description")
	if e != nil || d != s.Description {
		return errors.New("USB_NATIVE_FIREWALL_OWNERSHIP_CHANGED")
	}
	return nil
}
func firewallExpected(rule *wincom.Dispatch, s nativeRuleSpec, enabled int32) error {
	got, err := readFirewallConstraints(rule)
	if err != nil {
		return err
	}
	return verifyFirewallConstraints(got, s, enabled)
}
func createNativeRule(ctx context.Context, svc *wincom.Dispatch, p usbaddress.InterfaceProof, s nativeRuleSpec) error {
	portFields, e := nativeFirewallPortWriteFields(s)
	if e != nil {
		return e // Reject unsupported factory plans before any provider mutation.
	}
	// Unlike INetFwRule.Name (display name), CIM InstanceID retains the exact
	// protected journal selector used by setup, replay and all old cleanup paths.
	class, e := comObject(svc.Call("Get", wincom.String("MSFT_NetFirewallRule")))
	if e != nil {
		return e
	}
	defer class.Close()
	r, e := comObject(class.Call("SpawnInstance_", wincom.Int(0)))
	if e != nil {
		return e
	}
	defer r.Close()
	props := map[string]wincom.Value{"InstanceID": wincom.String(s.Name), "ElementName": wincom.String(s.Display), "RuleGroup": wincom.String(s.Group), "Description": wincom.String(s.Description), "Enabled": wincom.Int(2), "Action": wincom.Int(2), "Direction": wincom.Int(1), "Profiles": wincom.Int(0), "EdgeTraversalPolicy": wincom.Int(0), "LooseSourceMapping": wincom.Bool(false), "LocalOnlyMapping": wincom.Bool(false)}
	for name, v := range props {
		if e = cimSet(r, name, v); e != nil {
			return e
		}
	}
	if _, e = nativeRuleInterface(ctx, p); e != nil {
		return e
	}
	if e = cimPut(r, 2); e != nil {
		return e
	}
	installed, e := matchingRule(svc, s.Name)
	if e != nil || installed == nil {
		return errors.New("USB_NATIVE_FIREWALL_CREATION_UNCONFIRMED")
	}
	defer installed.Close()
	if e = firewallOwns(installed, s); e != nil {
		return e
	}
	if n, e := cimInt(installed, "Enabled"); e != nil || n != 2 {
		return errors.New("USB_NATIVE_FIREWALL_NEW_RULE_NOT_DISABLED")
	}

	portProperties := map[string]wincom.Value{"Protocol": wincom.String(fmt.Sprint(s.Protocol))}
	for _, field := range portFields {
		switch field {
		case "LocalPort":
			portProperties[field] = wincom.ArrayStrings(strings.Split(s.Ports, ","))
		case "RemotePort":
			portProperties[field] = wincom.ArrayStrings(strings.Split(s.RemotePorts, ","))
		case "IcmpType":
			portProperties[field] = wincom.ArrayStrings([]string{"8"})
		}
	}
	filters := []struct {
		class string
		props map[string]wincom.Value
	}{
		{"MSFT_NetApplicationFilter", map[string]wincom.Value{"AppPath": wincom.String(s.Program)}},
		{"MSFT_NetAddressFilter", map[string]wincom.Value{"LocalAddress": wincom.ArrayStrings(strings.Split(s.Local, ",")), "RemoteAddress": wincom.ArrayStrings(strings.Split(s.Remote, ","))}},
		{"MSFT_NetProtocolPortFilter", portProperties},
		{"MSFT_NetInterfaceFilter", map[string]wincom.Value{"InterfaceAlias": wincom.ArrayStrings([]string{s.Alias})}},
		{"MSFT_NetInterfaceTypeFilter", map[string]wincom.Value{"InterfaceType": wincom.UInt(0)}},
		{"MSFT_NetServiceFilter", map[string]wincom.Value{"ServiceName": wincom.String(s.Service)}},
		{"MSFT_NetNetworkLayerSecurityFilter", map[string]wincom.Value{"Authentication": wincom.UInt(0), "Encryption": wincom.UInt(0), "OverrideBlockRules": wincom.Bool(false), "LocalUsers": wincom.String(""), "RemoteUsers": wincom.String(""), "RemoteMachines": wincom.String("")}},
	}
	for _, f := range filters {
		d, e := cimRelated(installed, f.class)
		if e != nil {
			return e
		}
		for name, v := range f.props {
			if e = cimSet(d, name, v); e != nil {
				d.Close()
				return e
			}
		}
		if _, e = nativeRuleInterface(ctx, p); e != nil {
			d.Close()
			return e
		}
		e = cimPut(d, 1)
		d.Close()
		if e != nil {
			return e
		}
	}
	// The exact disabled scope must remain identical across two full fresh
	// readbacks. Unknown defaults or a changing rule never get enabled.
	var ready *wincom.Dispatch
	defer func() {
		if ready != nil {
			ready.Close()
		}
	}()
	_, e = verifyNativeRuleReadbacks(s, 2, "", func() (firewallConstraints, error) {
		if ready != nil {
			ready.Close()
			ready = nil
		}
		var err error
		ready, err = matchingRule(svc, s.Name)
		if err != nil {
			return nil, err
		}
		if ready == nil {
			return nil, errors.New("USB_NATIVE_FIREWALL_READBACK_ABSENT")
		}
		return readFirewallConstraints(ready)
	}, func() error {
		_, err := nativeRuleInterface(ctx, p)
		return err
	})
	if e != nil {
		return e
	}
	if e = cimSet(ready, "Enabled", wincom.Int(1)); e != nil {
		return e
	}
	return cimPut(ready, 1)
}
func ensureNativeRules(ctx context.Context, p usbaddress.InterfaceProof, specs []nativeRuleSpec, logger *log.Logger) error {
	return ensureNativeRulesMode(ctx, p, specs, false, logger)
}
func ensureNativeRulesMode(ctx context.Context, p usbaddress.InterfaceProof, specs []nativeRuleSpec, requireAbsent bool, logger *log.Logger) error {
	if ctx == nil {
		return errors.New("USB_NATIVE_FIREWALL_CONTEXT_REQUIRED")
	}
	release, lockErr := usbaddress.ConfigurationLock(ctx)
	if lockErr != nil {
		return lockErr
	}
	defer release()
	return nativeStep(logger, "firewall_rules", func() error {
		alias, e := nativeRuleInterface(ctx, p)
		if e != nil {
			return e
		}
		return withFirewall(ctx, func(svc *wincom.Dispatch) error {
			// Unsupported provider schemas fail before creating or reusing a rule.
			if e := nativeFirewallCreationPreflight(svc); e != nil {
				return e
			}
			for _, s := range specs {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if s.Alias != alias {
					return errors.New("USB_NATIVE_FIREWALL_ALIAS_CHANGED")
				}
				r, e := matchingRule(svc, s.Name)
				if e != nil {
					return e
				}
				keyBytes, _ := json.Marshal(s)
				key := string(keyBytes)
				reused := r != nil
				if r != nil {
					r.Close()
					if requireAbsent {
						return errors.New("USB_NATIVE_FIREWALL_NAME_ALREADY_EXISTS")
					}
				} else if e = createNativeRule(ctx, svc, p, s); e != nil {
					return e
				}
				nativeRuleCache.Lock()
				baseline := nativeRuleCache.hashes[key]
				nativeRuleCache.Unlock()
				hash, e := verifyNativeRuleReuse(s, baseline, func() (firewallConstraints, error) {
					actual, err := matchingRule(svc, s.Name)
					if err != nil {
						return nil, err
					}
					if actual == nil {
						return nil, errors.New("USB_NATIVE_FIREWALL_READBACK_ABSENT")
					}
					defer actual.Close()
					return readFirewallConstraints(actual)
				}, func() error {
					_, err := nativeRuleInterface(ctx, p)
					return err
				})
				if e != nil {
					return e
				}
				nativeRuleCache.Lock()
				if len(nativeRuleCache.hashes) >= 64 {
					nativeRuleCache.hashes = map[string]string{}
				}
				nativeRuleCache.hashes[key] = hash
				nativeRuleCache.Unlock()
				if logger != nil {
					logger.Printf("USB_NATIVE_FIREWALL_READBACK complete=true reused=%t", reused)
				}
			}
			return nil
		})
	})
}

// The fixed-name inspection path has no authority to mutate. Deletion requires
// a fresh caller-owned live session or complete fixed-adapter absence gate.
func removeNativeSessionRules(ctx context.Context, guid, token string, verifyOnly bool, logger *log.Logger) error {
	if !verifyOnly {
		return errors.New("USB_NATIVE_SESSION_CLEANUP_OWNER_REQUIRED")
	}
	return removeOwnedNativeSessionRules(ctx, guid, token, true, nil, logger)
}

func removeOwnedNativeSessionRules(ctx context.Context, guid, token string, verifyOnly bool, verifyOwner func() error, logger *log.Logger) error {
	if ctx == nil || (!verifyOnly && verifyOwner == nil) {
		return errors.New("USB_NATIVE_SESSION_CLEANUP_OWNER_REQUIRED")
	}
	if !strings.EqualFold(guid, NativeMacGUID) || !idPattern.MatchString(token) {
		return errors.New("USB_NATIVE_SESSION_RULE_SCOPE_INVALID")
	}
	specs, err := nativeSessionSpecs(token, usbaddress.Unified, false)
	if err != nil {
		return err
	}
	files, err := nativeSessionSpecs(token, usbaddress.Unified, true)
	if err != nil {
		return err
	}
	specs = append(specs, files...)
	endLock := shutdowntrace.Begin(shutdowntrace.PhaseMacRecoveryLock)
	release, err := usbaddress.ConfigurationLock(ctx)
	endLock()
	if err != nil {
		return err
	}
	defer release()
	verify := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return verifyOwner()
	}
	return nativeStep(logger, "firewall_cleanup", func() error {
		endRules := func() {}
		if verifyOnly {
			endRules = shutdowntrace.Begin(shutdowntrace.PhaseMacRecoveryRules)
		}
		defer endRules()
		return withFirewall(ctx, func(svc *wincom.Dispatch) error {
			read := func(spec nativeRuleSpec) (firewallConstraints, error) {
				r, err := matchingRule(svc, spec.Name)
				if err != nil {
					return nil, err
				}
				if r == nil {
					return nil, nil
				}
				defer r.Close()
				return readFirewallConstraints(r)
			}
			if verifyOnly {
				if err := ctx.Err(); err != nil {
					return err
				}
				names := make([]string, len(specs))
				for i, spec := range specs {
					names[i] = spec.Name
				}
				query, err := sessionRuleAbsenceQuery(token, names)
				if err != nil {
					return err
				}
				rows, err := comObject(svc.Call("ExecQuery", wincom.String(query), wincom.String("WQL"), wincom.Int(0)))
				if err != nil {
					return err
				}
				defer rows.Close()
				count, err := comInt(rows, "Count")
				if err = sessionRuleAbsenceCount(count, err); err != nil {
					return err
				}
				return ctx.Err()
			}
			err := executeNativeRuleCleanup(specs, read, verify, func(spec nativeRuleSpec, baseline string) error {
				// Retain the exact freshly queried provider object through Delete_.
				r, err := matchingRule(svc, spec.Name)
				if err != nil {
					return err
				}
				if r == nil {
					return errors.New("USB_NATIVE_FIREWALL_READBACK_ABSENT")
				}
				actual, err := readFirewallConstraints(r)
				if err == nil {
					var hash string
					hash, err = firewallFingerprint(actual)
					if err == nil && hash != baseline {
						err = errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_CHANGED")
					}
				}
				if err == nil {
					err = verify()
				}
				if err == nil {
					err = cimDelete(r)
				}
				r.Close()
				if err != nil {
					return err
				}
				if err = verify(); err != nil {
					return err
				}
				r, err = matchingRule(svc, spec.Name)
				if r != nil {
					r.Close()
					return errors.New("USB_NATIVE_SESSION_RULE_REMAINS")
				}
				return err
			})
			if err != nil {
				return err
			}
			// A rule absent during preflight must not silently appear afterwards.
			for _, spec := range specs {
				if err := verify(); err != nil {
					return err
				}
				r, err := matchingRule(svc, spec.Name)
				if err != nil {
					return err
				}
				if r != nil {
					r.Close()
					return errors.New("USB_NATIVE_SESSION_RULE_REMAINS")
				}
			}
			return verify()
		})
	})
}

func nativeCoreSpec(r coreRuleSpec, alias string) nativeRuleSpec {
	protocol := int32(6)
	if r.Protocol == "UDP" {
		protocol = 17
	}
	remotePorts := r.RemotePort
	if remotePorts == "" {
		remotePorts = "Any"
	}
	program, service := r.Program, r.Service
	if program == "" {
		program = "Any"
	}
	if service == "" {
		service = "Any"
	}
	return nativeRuleSpec{Name: r.Name, Display: "USB Link USB services", Group: serviceGroup, Description: serviceMarker, Program: program, Service: service, Alias: alias, Local: r.Local, Remote: r.Peer, Protocol: protocol, Ports: r.Ports, RemotePorts: remotePorts}
}
func EnsureSharedHostServicesNative(ctx context.Context, p usbaddress.InterfaceProof, executable string, logger *log.Logger) error {
	return nativeStep(logger, "shared_host_firewall", func() error {
		return ensureSharedHostServicesNative(ctx, p, executable, logger)
	})
}

func ensureSharedHostServicesNative(ctx context.Context, p usbaddress.InterfaceProof, executable string, logger *log.Logger) error {
	if !strings.EqualFold(p.GUID, usbaddress.HostGUID) || p.Role != "host" || p.Created <= 0 || !validCoreExecutable(executable) {
		return errors.New("USB_NATIVE_HOST_FIREWALL_SCOPE_INVALID")
	}
	alias, e := nativeRuleInterface(ctx, p)
	if e != nil {
		return e
	}
	rules := []coreRuleSpec{coreSpec(p.GUID, "USB-Link-Core-Host-Mac-v1", executable, "TCP", "10.6.9.1", "10.6.9.2", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")+",47775", "", ""), smbCoreSpec(p.GUID, "10.6.9.2"), coreSpec(p.GUID, "USB-Link-Core-Host-iPad-v1", executable, "TCP", "10.6.9.1", "10.6.9.3", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP"), "", ""), smbCoreSpec(p.GUID, "10.6.9.3")}
	specs := []nativeRuleSpec{}
	for _, r := range rules {
		specs = append(specs, nativeCoreSpec(r, alias))
	}
	return ensureNativeRules(ctx, p, specs, logger)
}
func EnsureCoreServicesNative(ctx context.Context, p usbaddress.InterfaceProof, peer, executable string, logger *log.Logger) error {
	if !strings.EqualFold(p.GUID, NativeMacGUID) || peer != "10.6.9.2" || !validCoreExecutable(executable) {
		return errors.New("USB_NATIVE_CORE_FIREWALL_SCOPE_INVALID")
	}
	if e := nativeMacScope(ctx, p); e != nil {
		return e
	}
	alias, e := nativeRuleInterface(ctx, p)
	if e != nil {
		return e
	}
	return ensureNativeRules(ctx, p, []nativeRuleSpec{nativeCoreSpec(coreSpec(p.GUID, "USB-Link-Core-Mac-v1", executable, "TCP", "10.6.9.1", peer, securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")+",47775", "", ""), alias), nativeCoreSpec(smbCoreSpec(p.GUID, peer), alias)}, logger)
}
func nativeSessionSpecs(token, profile string, files bool) ([]nativeRuleSpec, error) {
	if !idPattern.MatchString(token) || profile != usbaddress.Unified {
		return nil, errors.New("USB_NATIVE_SESSION_RULE_SCOPE_INVALID")
	}
	prefix := "Suhang-USB-Phase2-" + token
	base := nativeRuleSpec{Group: serviceGroup, Description: serviceMarker, Alias: "USB Link", Local: "10.6.9.1", Remote: "10.6.9.2", RemotePorts: "Any", Program: "Any", Service: "Any"}
	specs := []nativeRuleSpec{}
	add := func(suffix, ports string, protocol int32) {
		s := base
		s.Name = prefix + suffix
		s.Display = "USB Link USB services"
		s.Ports = ports
		s.Protocol = protocol
		if protocol == 1 {
			s.ICMP = "8"
			s.Ports = "Any"
		}
		specs = append(specs, s)
	}
	if files {
		add("-FILES", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP"), 6)
	} else {
		add("-ICMP", "", 1)
		add("-BENCH", securitypolicy.Ports(securitypolicy.NativeBenchmark, "TCP"), 6)
		add("-SUN-TCP", securitypolicy.InboundPorts("mac", "TCP"), 6)
		add("-SUN-UDP", securitypolicy.InboundPorts("mac", "UDP"), 17)
	}
	return specs, nil
}
func EnsureMacSessionRulesNative(ctx context.Context, p usbaddress.InterfaceProof, token, profile string, logger *log.Logger) error {
	if e := nativeMacScope(ctx, p); e != nil {
		return e
	}
	specs, e := nativeSessionSpecs(token, profile, false)
	if e != nil {
		return e
	}
	return ensureNativeRules(ctx, p, specs, logger)
}
func EnsureMacFileRuleNative(ctx context.Context, p usbaddress.InterfaceProof, token string, logger *log.Logger) error {
	if e := nativeMacScope(ctx, p); e != nil {
		return e
	}
	specs, e := nativeSessionSpecs(token, usbaddress.Unified, true)
	if e != nil {
		return e
	}
	return ensureNativeRules(ctx, p, specs, logger)
}
func CleanupMacSessionNative(ctx context.Context, guid, token string, logger *log.Logger) error {
	// Legacy callers have only a protected token journal. They may retire
	// complete fixed rules after complete native adapter absence, never while
	// a live same-GUID interface might belong to another session.
	return removeOwnedNativeSessionRules(ctx, guid, token, false, func() error {
		absent, err := MacAdapterAbsentNative()
		if err != nil {
			return err
		}
		if !absent {
			return errors.New("USB_NATIVE_SESSION_CLEANUP_LIVE_OWNER_REQUIRED")
		}
		return nil
	}, logger)
}
func VerifyMacCleanupNative(ctx context.Context, guid, token string, logger *log.Logger) error {
	if !strings.EqualFold(guid, NativeMacGUID) || !idPattern.MatchString(token) {
		return errors.New("USB_NATIVE_SESSION_RULE_SCOPE_INVALID")
	}
	if e := removeNativeSessionRules(ctx, guid, token, true, logger); e != nil {
		return e
	}
	return nativeStep(logger, "mac_adapter_absence", func() error {
		end := shutdowntrace.Begin(shutdowntrace.PhaseMacRecoveryAdapter)
		defer end()
		absent, e := MacAdapterAbsentNative()
		if e != nil {
			return e
		}
		if !absent {
			return errors.New("USB_NATIVE_MAC_STALE_ADAPTER_REQUIRES_OWNERSHIP_MIGRATION")
		}
		return nil
	})
}
