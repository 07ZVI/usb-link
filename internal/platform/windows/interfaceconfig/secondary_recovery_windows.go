//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
)

// RecoverPersistentMacSession never opens/creates/removes an adapter and never
// restores persistent settings. It only lets the launcher clean a completed
// protected session's exact token rules/peer route after source nonpresence or
// the complete saved current native+active+Store proof. Unknown creation phases
// and changed originals retain both journals.
func RecoverPersistentMacSession(ctx context.Context, dir string, s Scope, created int64, mode, sha string, cleanup func(usbaddress.InterfaceProof, func() error) error) error {
	if ctx == nil || s.Role != "mac" || validateScope(s) != nil || created <= 0 || !shaPattern.MatchString(sha) || cleanup == nil {
		return errors.New("USB_MAC_PERSISTENT_RECOVERY_INVALID")
	}
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	v, found, e := readSecondaryBinding(dir)
	if e != nil || !found {
		return errors.New("USB_MAC_PERSISTENT_RECOVERY_BINDING_UNPROVEN")
	}
	if v.CurrentScope != s || v.Created != created || v.Mode != mode || v.OriginalSHA256 != sha || (v.State != "ready" && v.State != "closed") {
		return errors.New("USB_MAC_PERSISTENT_RECOVERY_SESSION_CHANGED")
	}
	if _, e = exactSecondaryOriginal(dir, v); e != nil {
		return e
	}
	source := netconfig.VerifyOwnedMacFactorySourceNative(s.Index, s.LUID, v.Instance) == nil
	projected := s
	if source {
		row := windows.MibIfRow2{InterfaceLuid: s.LUID}
		if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row) == nil {
			if row.InterfaceLuid != s.LUID || !strings.EqualFold(row.InterfaceGuid.String(), s.GUID) || windows.UTF16ToString(row.Alias[:]) != "USB Link" || row.Type != 53 || row.InterfaceIndex == 0 {
				return errors.New("USB_MAC_PERSISTENT_RECOVERY_MAPPING_CHANGED")
			}
			projected.Index = row.InterfaceIndex
		}
	}
	verify := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		current, found, e := readSecondaryBinding(dir)
		if e != nil || !found || current != v {
			return errors.New("USB_MAC_PERSISTENT_RECOVERY_BINDING_CHANGED")
		}
		if _, e = exactSecondaryOriginal(dir, v); e != nil {
			return e
		}
		if source {
			return netconfig.VerifyOwnedMacFactorySourceNative(projected.Index, s.LUID, v.Instance)
		}
		if v.State != "ready" {
			return errors.New("USB_MAC_PERSISTENT_RECOVERY_SOURCE_UNPROVEN")
		}
		return netconfig.VerifyOwnedMacRecreatedNative(s.Index, s.LUID, v.Instance)
	}
	if e = verify(); e != nil {
		return e
	}
	if !source {
		profile := WintunProfileOps(s, verify, nil)
		a, e := verifyPersistentModeUnlocked(ctx, dir, s, verify, profile, "retained_runtime", created)
		if mode == "legacy" {
			a, e = verifyPersistentModeUnlocked(ctx, dir, s, verify, profile, "retained_legacy", created)
		}
		if e != nil || a.Created != created || a.ReceiptSHA256 != sha {
			return errors.New("USB_MAC_PERSISTENT_RECOVERY_ACTIVE_UNPROVEN")
		}
	}
	if e = cleanup(interfaceProof(projected), verify); e != nil {
		return e
	}
	if e = verify(); e != nil {
		return e
	}
	if source && v.State == "ready" {
		next := v
		next.State = "closed"
		return writeSecondaryBinding(dir, next, &v)
	}
	return nil
}
