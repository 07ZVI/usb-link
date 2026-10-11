//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"log"
	"suhang/usbnet/internal/platform/windows/wincom"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/ipadsession"
	"suhang/usbnet/internal/transport/usbaddress"
)

func EnsureIPadSessionRulesNative(ctx context.Context, p ipadsession.Plan, logger *log.Logger) error {
	if !p.Valid() || p.Version < 4 {
		return errors.New("USB_NATIVE_IPAD_RULE_PLAN_INVALID")
	}
	proof := usbaddress.InterfaceProof{Index: p.Index, GUID: p.GUID, LUID: p.LUID}
	alias, e := nativeRuleInterface(ctx, proof)
	if e != nil {
		return e
	}
	base := nativeRuleSpec{Group: p.Prefix(), Description: p.Marker(), Alias: alias, Program: "Any", Service: "Any", Local: "Any", Remote: "Any", RemotePorts: "Any"}
	specs := []nativeRuleSpec{}
	add := func(suffix, display, ports, remotePorts string, protocol int32, local, remote string) {
		s := base
		s.Name = p.Prefix() + suffix
		s.Display = display
		s.Protocol = protocol
		s.Ports = ports
		s.RemotePorts = remotePorts
		s.Local = local
		s.Remote = remote
		specs = append(specs, s)
	}
	add("-DHCP", "Suhang iPad USB DHCP trial", securitypolicy.Ports(securitypolicy.AddressAssignment, "UDP"), "68", 17, "Any", "Any")
	add("-MDNS", "Suhang iPad USB discovery trial", securitypolicy.Ports(securitypolicy.Discovery, "UDP"), "Any", 17, "Any", "Any")
	add("-TCP", "Suhang iPad USB application TCP trial", securitypolicy.InboundPorts("ipad", "TCP"), "Any", 6, p.ServerIP, p.PeerIP())
	add("-UDP", "Suhang iPad USB Sunshine UDP trial", securitypolicy.InboundPorts("ipad", "UDP"), "Any", 17, p.ServerIP, p.PeerIP())
	return ensureNativeRulesMode(ctx, proof, specs, true, logger)
}
func EnsureIPadCoreServicesNative(ctx context.Context, p usbaddress.InterfaceProof, peer, executable string, logger *log.Logger) error {
	if peer != "10.6.9.3" || p.Role != "" || !validCoreExecutable(executable) {
		return errors.New("USB_NATIVE_IPAD_CORE_RULE_SCOPE_INVALID")
	}
	alias, e := nativeRuleInterface(ctx, p)
	if e != nil {
		return e
	}
	specs := []nativeRuleSpec{
		nativeCoreSpec(coreSpec(p.GUID, "USB-Link-Core-iPad-v1", executable, "TCP", "10.6.9.1", peer, securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP"), "", ""), alias),
		nativeCoreSpec(smbCoreSpec(p.GUID, peer), alias),
		nativeCoreSpec(coreSpec(p.GUID, "USB-Link-Core-DHCP-v1", executable, "UDP", "Any", "Any", "67", "68", ""), alias),
		nativeCoreSpec(coreSpec(p.GUID, "USB-Link-Core-MDNS-v1", executable, "UDP", "Any", "Any", "5353", "", ""), alias),
	}
	return ensureNativeRules(ctx, p, specs, logger)
}
func CleanupIPadSessionRulesNative(ctx context.Context, p ipadsession.Plan, logger *log.Logger) error {
	if !p.Valid() {
		return errors.New("USB_NATIVE_IPAD_RULE_PLAN_INVALID")
	}
	names := []string{}
	for _, suffix := range []string{"-DHCP", "-MDNS", "-TCP", "-UDP"} {
		names = append(names, p.Prefix()+suffix)
	}
	return removeMarkedNativeRules(ctx, names, p.Prefix(), p.Marker(), logger)
}
func removeMarkedNativeRules(ctx context.Context, names []string, group, marker string, logger *log.Logger) error {
	if ctx == nil {
		return errors.New("USB_NATIVE_FIREWALL_CONTEXT_REQUIRED")
	}
	release, err := usbaddress.ConfigurationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return nativeStep(logger, "marked_firewall_cleanup", func() error {
		return withFirewall(ctx, func(svc *wincom.Dispatch) error {
			for _, name := range names {
				r, e := matchingRule(svc, name)
				if e != nil {
					return e
				}
				if r == nil {
					continue
				}
				if e = firewallOwns(r, nativeRuleSpec{Group: group, Description: marker}); e == nil {
					e = ctx.Err()
				}
				if e == nil {
					e = cimDelete(r)
				}
				r.Close()
				if e != nil {
					return e
				}
				r, e = matchingRule(svc, name)
				if r != nil {
					r.Close()
					return errors.New("USB_NATIVE_MARKED_RULE_REMAINS")
				}
				if e != nil {
					return e
				}
			}
			return nil
		})
	})
}
func RemoveCoreServicesNative(ctx context.Context, logger *log.Logger) error {
	return removeMarkedNativeRules(ctx, []string{"USB-Link-Core-Mac-v1", "USB-Link-Core-iPad-v1", "USB-Link-Core-DHCP-v1", "USB-Link-Core-MDNS-v1", "USB-Link-Core-Host-Mac-v1", "USB-Link-Core-Host-iPad-v1"}, serviceGroup, serviceMarker, logger)
}
