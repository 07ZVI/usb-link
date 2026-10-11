//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/platform/windows/wincom"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NativeReadCompatibility is a one-shot observation of the current shared host
// only. p must be the caller's actual PreparedProof, not a GUID-derived mapping.
// executable must be this core process's already-verified source. No result is
// an authorization/cache entry, Ready proof, or evidence of provider writes.
// No native-network flag, logger, timer, COM setter, or mutation API is used.
func NativeReadCompatibility(ctx context.Context, p usbaddress.InterfaceProof, executable string) (out NativeReadCompatibilityReport) {
	out = NativeReadCompatibilityReport{Schema: 1, ReadOnly: true, WriteSupport: "unproven", Status: "input_unavailable", Stages: []NativeReadCompatibilityStage{}}
	self, err := os.Executable()
	if ctx == nil || err != nil || !validCoreExecutable(executable) || !strings.EqualFold(filepath.Clean(self), filepath.Clean(executable)) || p.Role != "host" || p.Created <= 0 || !strings.EqualFold(p.GUID, usbaddress.HostGUID) {
		return out
	}
	defer func() {
		if ctx.Err() != nil {
			out.Status = "cancelled"
		}
	}()
	alias, err := nativeRuleInterface(ctx, p)
	if err != nil {
		out.Stages = append(out.Stages, nativeReadFailedStage("interface_identity", "host", err))
		return out
	}
	verify := func() error {
		currentAlias, e := nativeRuleInterface(ctx, p)
		if e != nil {
			return e
		}
		if currentAlias != alias {
			return errors.New("interface alias changed")
		}
		return nil
	}
	// Take the existing configuration lock only for bounded reads. No HostJoin,
	// preparation, process launch, or topology mutation runs under this lock.
	release, err := usbaddress.ConfigurationLock(ctx)
	if err != nil {
		out.Stages = append(out.Stages, nativeReadFailedStage("configuration_observation", "host", err))
		return out
	}
	defer release()
	if err = verify(); err != nil {
		out.Stages = append(out.Stages, nativeReadFailedStage("interface_identity", "host", err))
		return out
	}
	out.Status = "read_compatible"
	out.Stages = append(out.Stages, NativeReadCompatibilityStage{Phase: "interface_identity", Selector: "host", Status: "match"})
	appendStage := func(s NativeReadCompatibilityStage) {
		if e := verify(); e != nil {
			s = nativeReadFailedStage(s.Phase, s.Selector, e)
			s.Status = "scope_changed_or_unavailable"
		}
		if s.Status != "match" && s.Status != "absent_profile" {
			out.Status = "read_mismatch_or_unavailable"
		}
		out.Stages = append(out.Stages, s)
	}
	appendStage(nativeReadIPInterface(p))
	if ctx.Err() != nil {
		return out
	}
	appendStage(nativeReadDHCP(p))
	if ctx.Err() != nil {
		return out
	}
	profile := NativeReadCompatibilityStage{Phase: "private_profile_read", Selector: "host", Status: "unavailable"}
	err = wincom.WithApartment(func() error {
		network, guid, category, e := nlmRead(ctx, p)
		defer nlmRelease(network)
		if e != nil {
			return e
		}
		if guid == "" {
			profile.Status = "absent_profile"
			return nil
		}
		profile.Status = "match"
		profile.Fields = []NativeReadCompatibilityField{
			{Class: "INetwork", Property: "ExclusiveAdapterConnection", Status: "match", Projection: "unique"},
			nativeReadNumber("INetwork", "Category", category, category <= 1),
		}
		return nil
	})
	if err != nil {
		profile = nativeReadFailedStage(profile.Phase, profile.Selector, err)
	}
	appendStage(profile)
	if ctx.Err() != nil {
		return out
	}
	rules := []coreRuleSpec{
		coreSpec(p.GUID, "USB-Link-Core-Host-Mac-v1", executable, "TCP", "10.6.9.1", "10.6.9.2", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")+",47775", "", ""),
		smbCoreSpec(p.GUID, "10.6.9.2"),
		coreSpec(p.GUID, "USB-Link-Core-Host-iPad-v1", executable, "TCP", "10.6.9.1", "10.6.9.3", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP"), "", ""),
		smbCoreSpec(p.GUID, "10.6.9.3"),
	}
	selectors := []string{"host_mac", "smb_mac", "host_ipad", "smb_ipad"}
	for i, r := range rules {
		if ctx.Err() != nil {
			break
		}
		s := nativeCoreSpec(r, alias)
		stage := NativeReadCompatibilityStage{Phase: "firewall_read", Selector: selectors[i], Status: "unavailable"}
		err = withFirewall(ctx, func(svc *wincom.Dispatch) error {
			if e := verify(); e != nil {
				return e
			}
			rule, e := matchingRule(svc, s.Name)
			if e != nil {
				return e
			}
			if rule == nil {
				stage.Status = "absent_rule"
				return nil
			}
			defer rule.Close()
			got, observed := nativeReadFirewallFields(ctx, rule)
			stage.Fields = nativeFirewallReadDifferences(s, got, observed)
			stage.Status = "field_mismatch_or_unavailable"
			if nativeReadStageFieldsMatch(stage.Fields) {
				stage.Status = "match"
			}
			return nil
		})
		if err != nil {
			stage = nativeReadFailedStage(stage.Phase, stage.Selector, err)
		}
		appendStage(stage)
	}
	return out
}

func nativeReadFailedStage(phase, selector string, err error) NativeReadCompatibilityStage {
	hr, code := nativeReadErrorNumbers(err)
	return NativeReadCompatibilityStage{Phase: phase, Selector: selector, Status: "unavailable", HRESULT: hr, NativeError: code}
}
func nativeReadNumber(class, property string, n uint32, matches bool) NativeReadCompatibilityField {
	s := "mismatch"
	if matches {
		s = "match"
	}
	return NativeReadCompatibilityField{Class: class, Property: property, Status: s, Projection: "unsigned_integer", Number: &n}
}
func nativeReadIPInterface(p usbaddress.InterfaceProof) NativeReadCompatibilityStage {
	s := NativeReadCompatibilityStage{Phase: "ipv4_interface_read", Selector: "host", Status: "unavailable"}
	r := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if e := windows.GetIpInterfaceEntry(&r); e != nil {
		return nativeReadFailedStage(s.Phase, s.Selector, e)
	}
	if r.InterfaceIndex != p.Index || r.InterfaceLuid != p.LUID {
		return s
	}
	// Host MTU is negotiated separately; these are the existing supported
	// values, not a claim that an initial 1500 plan equals the live jumbo plan.
	s.Fields = []NativeReadCompatibilityField{
		nativeReadNumber("MIB_IPINTERFACE_ROW", "NlMtu", r.NlMtu, r.NlMtu == 1500 || r.NlMtu == 9000 || r.NlMtu == 16000),
		nativeReadNumber("MIB_IPINTERFACE_ROW", "WeakHostSend", uint32(r.WeakHostSend), r.WeakHostSend == 1),
		nativeReadNumber("MIB_IPINTERFACE_ROW", "WeakHostReceive", uint32(r.WeakHostReceive), r.WeakHostReceive == 1),
		nativeReadNumber("MIB_IPINTERFACE_ROW", "ForwardingEnabled", uint32(r.ForwardingEnabled), r.ForwardingEnabled == 1),
	}
	s.Status = "field_mismatch_or_unavailable"
	if nativeReadStageFieldsMatch(s.Fields) {
		s.Status = "match"
	}
	return s
}
func nativeReadDHCP(p usbaddress.InterfaceProof) NativeReadCompatibilityStage {
	s := NativeReadCompatibilityStage{Phase: "dhcp_read", Selector: "host", Status: "unavailable"}
	size := uint32(16 * 1024)
	for tries := 0; tries < 3; tries++ {
		if size == 0 || size > 4*1024*1024 {
			return s
		}
		b := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
		e := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, first, &size)
		if e == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if e != nil {
			return nativeReadFailedStage(s.Phase, s.Selector, e)
		}
		count, value := 0, uint32(0)
		for a, n := first, 0; a != nil; a, n = a.Next, n+1 {
			if n >= 65536 {
				return s
			}
			if a.Luid != p.LUID && a.IfIndex != p.Index {
				continue
			}
			count++
			if a.Luid != p.LUID || a.IfIndex != p.Index {
				return s
			}
			if a.Flags&4 != 0 {
				value = 1
			} // IP_ADAPTER_DHCP_ENABLED.
		}
		runtime.KeepAlive(b)
		if count != 1 {
			return s
		}
		s.Fields = []NativeReadCompatibilityField{nativeReadNumber("IP_ADAPTER_ADDRESSES", "DhcpEnabled", value, value == 0)}
		s.Status = "field_mismatch_or_unavailable"
		if value == 0 {
			s.Status = "match"
		}
		return s
	}
	return s
}

func nativeReadFirewallField(d *wincom.Dispatch, field string) ([]string, NativeReadCompatibilityField) {
	meta := NativeReadCompatibilityField{Status: "unavailable"}
	v, e := cimProperty(d, field)
	defer v.Clear()
	if e != nil {
		meta.HRESULT, meta.NativeError = nativeReadErrorNumbers(e)
		return nil, meta
	}
	// Getters require the actual typed projection. Never include any string,
	// array, program, alias, network, account, or identity value in metadata.
	switch {
	case v.IsNull():
		meta.Projection = "null"
	case v.IsEmpty():
		meta.Projection = "empty"
	default:
		if _, e := v.String(); e == nil {
			meta.Projection = "string"
		} else if _, e := v.Strings(64); e == nil {
			meta.Projection = "string_array"
		} else if n, e := v.UInt(); e == nil {
			meta.Projection = "unsigned_integer"
			meta.Number = &n
		} else if _, e := v.Bool(); e == nil {
			meta.Projection = "boolean"
		} else {
			meta.Projection = "unknown"
		}
	}
	parts, e := constraintValues(v, field)
	if e != nil {
		meta.Status = "type_unknown"
		meta.HRESULT, meta.NativeError = nativeReadErrorNumbers(e)
		return nil, meta
	}
	meta.Status = "observed"
	return parts, meta
}

func nativeReadFirewallFields(ctx context.Context, rule *wincom.Dispatch) (firewallConstraints, map[string]NativeReadCompatibilityField) {
	got, observed := firewallConstraints{}, map[string]NativeReadCompatibilityField{}
	var addr *wincom.Dispatch
	defer func() {
		if addr != nil {
			addr.Close()
		}
	}()
	for _, g := range firewallGroups {
		if ctx.Err() != nil {
			return got, observed
		}
		d := rule
		var e error
		if g.class != "" {
			d, e = cimRelated(rule, g.class)
		}
		if e != nil {
			hr, code := nativeReadErrorNumbers(e)
			for _, f := range g.fields {
				observed[firewallField(g.class, f)] = NativeReadCompatibilityField{HRESULT: hr, NativeError: code}
			}
			continue
		}
		for _, f := range g.fields {
			if ctx.Err() != nil {
				break
			}
			parts, meta := nativeReadFirewallField(d, f)
			key := firewallField(g.class, f)
			observed[key] = meta
			if meta.Status == "observed" {
				got[key] = parts
			}
		}
		if g.class == "MSFT_NetAddressFilter" {
			addr = d
		} else if g.class != "" {
			d.Close()
		}
	}
	if ctx.Err() != nil {
		return got, observed
	}
	rv, re := cimProperty(rule, "RemoteDynamicKeywordAddresses")
	defer rv.Clear()
	av, ae := wincom.Empty(), errors.New("address filter unavailable")
	if addr != nil {
		av, ae = cimProperty(addr, "RemoteDynamicKeywordAddresses")
	}
	defer av.Clear()
	if (re == nil) == (ae == nil) {
		hr, code := nativeReadErrorNumbers(re)
		if hr == 0 && code == 0 {
			hr, code = nativeReadErrorNumbers(ae)
		}
		observed["/RemoteDynamicKeywordAddresses"] = NativeReadCompatibilityField{HRESULT: hr, NativeError: code}
		return got, observed
	}
	d, where := rule, "RULE"
	if ae == nil {
		d, where = addr, "ADDRESS"
	}
	parts, meta := nativeReadFirewallField(d, "RemoteDynamicKeywordAddresses")
	observed["/RemoteDynamicKeywordAddresses"] = meta
	if meta.Status == "observed" {
		got["/RemoteDynamicKeywordAddresses"] = parts
		got["/dynamic_source"] = firewallParts(where)
		observed["/dynamic_source"] = NativeReadCompatibilityField{Projection: "fixed_location"}
	}
	return got, observed
}
