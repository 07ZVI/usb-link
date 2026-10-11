//go:build windows && amd64

package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/platform/windows/wincom"
)

const legacyMaintenanceRule = "Suhang-Remote-Update-7c494949-v1"

// CleanupLegacyMaintenanceNative deletes only the complete fixed legacy rule
// for an executable independently verified by the protected installer. A name
// or group alone never authorizes deletion. Measurement intent is not supplied
// here: any remaining measurement rule is an explicit fence, not swept away.
func CleanupLegacyMaintenanceNative(ctx context.Context, verifyOwnedExecutable func(string) error) error {
	if ctx == nil || verifyOwnedExecutable == nil {
		return errors.New("USB_NATIVE_REMOTE_OWNER_REQUIRED")
	}
	release, err := usbaddress.ConfigurationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return nativeStep(nil, "remote_legacy_cleanup", func() error {
		return withFirewall(ctx, func(svc *wincom.Dispatch) error {
			for _, name := range []string{"Suhang-USB-Latency-Mac-v1", "Suhang-USB-Latency-ICMP-Mac-v1"} {
				r, e := matchingRule(svc, name)
				if r != nil {
					r.Close()
					return errors.New("USB_NATIVE_REMOTE_MEASUREMENT_INTENT_REQUIRED")
				}
				if e != nil {
					return e
				}
			}
			r, e := matchingRule(svc, legacyMaintenanceRule)
			if e != nil || r == nil {
				return e
			}
			defer r.Close()
			program, fingerprint, e := legacyMaintenanceOwnership(r)
			if e != nil {
				return e
			}
			if e = verifyOwnedExecutable(program); e != nil {
				return errors.New("USB_NATIVE_REMOTE_EXECUTABLE_OWNERSHIP_UNPROVEN")
			}
			fresh, e := matchingRule(svc, legacyMaintenanceRule)
			if e != nil || fresh == nil {
				return errors.New("USB_NATIVE_REMOTE_RULE_CHANGED")
			}
			defer fresh.Close()
			fp, hash, e := legacyMaintenanceOwnership(fresh)
			if e != nil || fp != program || hash != fingerprint {
				return errors.New("USB_NATIVE_REMOTE_RULE_CHANGED")
			}
			if e = verifyOwnedExecutable(fp); e != nil {
				return errors.New("USB_NATIVE_REMOTE_EXECUTABLE_OWNERSHIP_UNPROVEN")
			}
			if e = ctx.Err(); e != nil {
				return e
			}
			if e = cimDelete(fresh); e != nil {
				return e
			}
			remaining, e := matchingRule(svc, legacyMaintenanceRule)
			if remaining != nil {
				remaining.Close()
				return errors.New("USB_NATIVE_REMOTE_RULE_REMAINS")
			}
			return e
		})
	})
}

func legacyMaintenanceOwnership(rule *wincom.Dispatch) (program, fingerprint string, err error) {
	app, e := cimRelated(rule, "MSFT_NetApplicationFilter")
	if e != nil {
		return "", "", e
	}
	defer app.Close()
	program, e = cimString(app, "AppPath")
	if e != nil || !validCoreExecutable(program) {
		return "", "", errors.New("USB_NATIVE_REMOTE_PROGRAM_UNPROVEN")
	}
	spec := nativeRuleSpec{Name: legacyMaintenanceRule, Display: "USB Link signed upgrades", Group: "Suhang-Remote-Maintenance-v1", Description: "", Program: program, Service: "Any", Alias: "USB Link", Local: "10.6.9.1", Remote: "10.6.9.2", Ports: "47775", RemotePorts: "Any", Protocol: 6}
	if e = firewallExpected(rule, spec, 1); e != nil {
		return "", "", e
	}
	display, e := cimString(rule, "DisplayName")
	if e != nil || display != spec.Display {
		return "", "", errors.New("USB_NATIVE_REMOTE_DISPLAY_CHANGED")
	}
	// Reject additional scoping/identity constraints instead of interpreting
	// them as a legacy rule that merely happens to carry the expected name.
	for _, field := range []string{"Owner", "Platforms", "PackageFamilyName", "PolicyAppId", "RemoteDynamicKeywordAddresses"} {
		v, e := cimProperty(rule, field)
		if e != nil {
			v.Clear()
			return "", "", errors.New("USB_NATIVE_REMOTE_ADDITIONAL_CONSTRAINT_UNKNOWN")
		}
		parts, pe := constraintValues(v, field)
		if v.IsNull() {
			parts, pe = []string{"NULL"}, nil
		}
		v.Clear()
		if pe != nil || !unrestrictedLegacyConstraint(parts, false) {
			return "", "", errors.New("USB_NATIVE_REMOTE_ADDITIONAL_CONSTRAINT_CHANGED")
		}
	}
	for _, field := range []string{"LooseSourceMapping", "LocalOnlyMapping"} {
		v, e := cimProperty(rule, field)
		if e != nil {
			v.Clear()
			return "", "", e
		}
		b, be := v.Bool()
		v.Clear()
		if be != nil || b {
			return "", "", errors.New("USB_NATIVE_REMOTE_MAPPING_CHANGED")
		}
	}
	packageValue, e := cimProperty(app, "Package")
	if e != nil {
		packageValue.Clear()
		return "", "", e
	}
	parts, pe := constraintValues(packageValue, "Package")
	packageValue.Clear()
	if pe != nil || !unrestrictedLegacyConstraint(parts, true) {
		return "", "", errors.New("USB_NATIVE_REMOTE_PACKAGE_CHANGED")
	}
	port, e := cimRelated(rule, "MSFT_NetProtocolPortFilter")
	if e != nil {
		return "", "", e
	}
	defer port.Close()
	dynamic, e := cimInt(port, "DynamicTransport")
	if e != nil || dynamic != 0 {
		return "", "", errors.New("USB_NATIVE_REMOTE_DYNAMIC_TRANSPORT_CHANGED")
	}
	v, e := cimProperty(port, "IcmpType")
	if e != nil {
		v.Clear()
		return "", "", e
	}
	parts, pe = constraintValues(v, "IcmpType")
	v.Clear()
	if pe != nil || !unrestrictedLegacyConstraint(parts, true) {
		return "", "", errors.New("USB_NATIVE_REMOTE_ICMP_CHANGED")
	}
	fingerprint, err = firewallConstraintSnapshot(rule)
	return program, fingerprint, err
}

func verifyNativeRuleBaseline(rule *wincom.Dispatch, spec nativeRuleSpec) error {
	b, e := json.Marshal(spec)
	if e != nil {
		return e
	}
	nativeRuleCache.Lock()
	baseline := nativeRuleCache.hashes[string(b)]
	nativeRuleCache.Unlock()
	if baseline == "" {
		return errors.New("USB_NATIVE_REMOTE_CORE_BASELINE_UNAVAILABLE")
	}
	hash, e := firewallConstraintSnapshot(rule)
	if e != nil || hash != baseline {
		return errors.New("USB_NATIVE_REMOTE_CORE_BASELINE_CHANGED")
	}
	return nil
}

// VerifyMaintenanceCoverageNative is read-only. Only this process's earlier
// complete native readback can supply the baseline; it cannot adopt an unknown
// rule after restart, recreate one, or turn a diagnostic into authorization.
func VerifyMaintenanceCoverageNative(ctx context.Context, host usbaddress.InterfaceProof, executable string, verifyGeneration func() error) error {
	if ctx == nil || verifyGeneration == nil || host.Role != "host" || !strings.EqualFold(host.GUID, usbaddress.HostGUID) || !validCoreExecutable(executable) {
		return errors.New("USB_NATIVE_REMOTE_HOST_SCOPE_INVALID")
	}
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return e
	}
	defer release()
	return nativeStep(nil, "remote_coverage_read", func() error {
		if e := verifyGeneration(); e != nil {
			return e
		}
		alias, e := nativeRuleInterface(ctx, host)
		if e != nil {
			return e
		}
		spec := nativeCoreSpec(coreSpec(host.GUID, "USB-Link-Core-Host-Mac-v1", executable, "TCP", "10.6.9.1", "10.6.9.2", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")+",47775", "", ""), alias)
		return withFirewall(ctx, func(svc *wincom.Dispatch) error {
			if e := verifyGeneration(); e != nil {
				return e
			}
			r, e := matchingRule(svc, spec.Name)
			if e != nil || r == nil {
				return errors.New("USB_NATIVE_REMOTE_CORE_RULE_ABSENT")
			}
			defer r.Close()
			if e = firewallExpected(r, spec, 1); e != nil {
				return e
			}
			if e = verifyNativeRuleBaseline(r, spec); e != nil {
				return e
			}
			if _, e = nativeRuleInterface(ctx, host); e != nil {
				return e
			}
			return verifyGeneration()
		})
	})
}
