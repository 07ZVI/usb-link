//go:build windows && amd64

package netconfig

import (
	"context"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/platform/windows/wincom"
)

func residentDiagnosticNames(role string) ([]string, int) {
	switch role {
	case "host":
		return []string{"USB-Link-Core-Host-Mac-v1", "USB-Link-Core-Host-iPad-v1", "USB-Link-Native-SMB-" + usbaddress.HostGUID + "-10-6-9-2", "USB-Link-Native-SMB-" + usbaddress.HostGUID + "-10-6-9-3"}, 4
	case "mac":
		return []string{"USB-Link-Resident-Mac-ICMP-v1", "USB-Link-Resident-Mac-BENCH-v1", "USB-Link-Resident-Mac-SUN-TCP-v1", "USB-Link-Resident-Mac-SUN-UDP-v1", "USB-Link-Resident-Mac-FILES-v1"}, 5
	case "ipad":
		return []string{"USB-Link-Resident-iPad-DHCP-v1", "USB-Link-Resident-iPad-MDNS-v1", "USB-Link-Resident-iPad-TCP-v1", "USB-Link-Resident-iPad-UDP-v1"}, 4
	case "core_mac":
		return []string{"USB-Link-Core-Mac-v1", "USB-Link-Native-SMB-" + NativeMacGUID + "-10-6-9-2"}, 2
	case "core_ipad":
		return []string{"USB-Link-Core-iPad-v1", "USB-Link-Core-DHCP-v1", "USB-Link-Core-MDNS-v1"}, 4
	}
	return nil, 0
}

// One-shot observation only; caller supplies fresh verified installed-core
// authority. No live adapter is inferred. Only protected ledger phase and
// fixed exact-name presence are read, never constraints compared as Ready.
// Context bounds cooperative checks; synchronous COM calls are not preempted.
func ResidentFirewallDiagnostics(ctx context.Context, dir string, owner func() error) (out ResidentFirewallDiagnosticReport) {
	out = ResidentFirewallDiagnosticReport{Schema: 1, ReadOnly: true, Scope: "PROTECTED_LEDGER_AND_FIXED_NAME_COUNTS_NOT_READY_OR_WRITE_AUTHORITY", Status: "unavailable", Roles: []ResidentFirewallDiagnosticRole{}}
	if ctx == nil || owner == nil {
		return out
	}
	verify := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return owner()
	}
	if verify() != nil {
		return out
	}
	history := ResidentFirewallFailureDiagnostics()
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return out
	}
	defer release()
	out.Status = "observed"
	for i, role := range residentRoles {
		row := ResidentFirewallDiagnosticRole{Role: role, Phase: "ledger_absent", Failure: history[i]}
		names, expected := residentDiagnosticNames(role)
		row.ExpectedRuleCount = expected
		fail := func(e error) {
			if row.ObservationErrorCode == "" {
				detail := ResidentFirewallErrorDetails(e)
				row.ObservationErrorCode, row.ObservationField = detail.Code, detail.Field
				row.HRESULT, row.NativeError = detail.HRESULT, detail.NativeError
			}
			out.Status = "partly_unavailable"
		}
		if e = verify(); e != nil {
			fail(e)
			out.Roles = append(out.Roles, row)
			break
		}
		b, found, e := readResidentLedgerFile(dir, role)
		row.LedgerPresent = found
		if e != nil {
			row.Phase = "ledger_unreadable"
			fail(e)
		} else if found {
			v, er := decodeResidentLedger(b)
			if er != nil {
				row.Phase = "ledger_unreadable"
				fail(er)
			} else {
				row.Phase = v.Phase
				names = nil
				for _, s := range v.Specs {
					names = append(names, s.Name)
				}
			}
		}
		row.KnownNameCount = len(names)
		e = withFirewall(ctx, func(svc *wincom.Dispatch) error {
			for _, name := range names {
				if er := verify(); er != nil {
					return er
				}
				r, er := matchingRule(svc, name)
				if er != nil {
					row.UnreadableRules++
					if row.ObservationErrorCode == "" {
						fail(er)
					}
					continue
				}
				present := r != nil
				if r != nil {
					r.Close()
				}
				if er = verify(); er != nil {
					return er
				}
				if present {
					row.PresentRules++
				} else {
					row.AbsentRules++
				}
			}
			return verify()
		})
		if e != nil {
			fail(e)
		}
		out.Roles = append(out.Roles, row)
	}
	if verify() != nil {
		out.Status = "cancelled_or_owner_unavailable"
	}
	return out
}
