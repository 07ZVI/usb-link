//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"log"
	"strings"
	"suhang/usbnet/internal/platform/windows/wincom"
	"unsafe"
)

func profileRecoveryMapping(ctx context.Context, p OwnedProfileRecoveryIdentity) error {
	if ctx == nil || validateProfileRecoveryScope(p) != nil {
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_SCOPE_INVALID")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	var table *windows.MibIfTable2
	if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table) != nil || table == nil {
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_MAPPING_UNREADABLE")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_MAPPING_UNREADABLE")
	}
	rows := make([]nativeHostInterface, 0, table.NumEntries)
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		rows = append(rows, nativeHostInterface{GUID: r.InterfaceGuid.String(), Alias: windows.UTF16ToString(r.Alias[:]), Type: r.Type, Index: r.InterfaceIndex, LUID: r.InterfaceLuid})
	}
	if e := validateProfileRecoveryMapping(p, rows); e != nil {
		return e
	}
	parsed, e := windows.GUIDFromString(p.GUID)
	if e != nil {
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_SCOPE_INVALID")
	}
	var mapped uint64
	rc, _, _ := hostIP.NewProc("ConvertInterfaceGuidToLuid").Call(uintptr(unsafe.Pointer(&parsed)), uintptr(unsafe.Pointer(&mapped)))
	r := windows.MibIfRow2{InterfaceLuid: p.LUID}
	if rc != 0 || mapped != p.LUID || windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r) != nil {
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_MAPPING_CHANGED")
	}
	return validateProfileRecoveryMapping(p, []nativeHostInterface{{GUID: r.InterfaceGuid.String(), Alias: windows.UTF16ToString(r.Alias[:]), Type: r.Type, Index: r.InterfaceIndex, LUID: r.InterfaceLuid}})
}
func profileRecoveryMacNode(p OwnedProfileRecoveryIdentity) (nativeHostNode, error) {
	class, _ := windows.GUIDFromString(hostNetClass)
	// Complete installed NET set includes phantom duplicates; only the single
	// healthy exact GUID binding is admitted. No registry path is inferred.
	set, e := windows.SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")
	if e != nil {
		return nativeHostNode{}, errors.New("USB_NATIVE_PROFILE_RECOVERY_PNP_UNREADABLE")
	}
	defer set.Close()
	var found nativeHostNode
	count := 0
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			if count == 1 {
				return found, nil
			}
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_PNP_NOT_UNIQUE")
		}
		if e != nil {
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_PNP_UNREADABLE")
		}
		key, e := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if e == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if e != nil {
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_BINDING_UNREADABLE")
		}
		guid, present, e := nativeHostRegistryGUID(key)
		windows.RegCloseKey(key)
		if e != nil {
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_BINDING_UNREADABLE")
		}
		if !present || !strings.EqualFold(guid, p.GUID) {
			continue
		}
		count++
		if count != 1 {
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_PNP_NOT_UNIQUE")
		}
		found, e = readNativeWintunNodeForGUID(set, info, guid, p.GUID)
		if e != nil {
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_DRIVER_UNPROVEN")
		}
		id, e := windows.UTF16PtrFromString(found.Instance)
		if e != nil {
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_DRIVER_UNPROVEN")
		}
		var dev windows.DEVINST
		rc, _, _ := hostCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&dev)), uintptr(unsafe.Pointer(id)), 0)
		var status, problem uint32
		if rc != 0 || dev == 0 || dev != info.DevInst || windows.CM_Get_DevNode_Status(&status, &problem, dev, 0) != nil || problem != 0 || status&windows.DN_NEED_RESTART != 0 {
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_DRIVER_UNPROVEN")
		}
		flags, e := set.DeviceInstallParams(info)
		if e != nil || flags.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0 {
			return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_RESTART_UNPROVEN")
		}
	}
	return found, errors.New("USB_NATIVE_PROFILE_RECOVERY_PNP_LIMIT")
}
func verifyProfileRecoveryIdentity(ctx context.Context, p OwnedProfileRecoveryIdentity, verifyOwnedOriginal func() error) error {
	if ctx == nil || verifyOwnedOriginal == nil || validateProfileRecoveryScope(p) != nil {
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_OWNER_REQUIRED")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return runProfileRecoveryIdentity(func() error {
		if e := verifyOwnedOriginal(); e != nil {
			return errors.New("USB_NATIVE_PROFILE_RECOVERY_OWNER_UNPROVEN")
		}
		return ctx.Err()
	}, func() error { return profileRecoveryMapping(ctx, p) }, func() error {
		if p.Role == "host" {
			if e := VerifySharedHostIdentityNative(p.Index); e != nil {
				return errors.New("USB_NATIVE_PROFILE_RECOVERY_DRIVER_UNPROVEN")
			}
			return nil
		}
		a, e := profileRecoveryMacNode(p)
		if e != nil {
			return e
		}
		b, e := profileRecoveryMacNode(p)
		if e != nil {
			return e
		}
		if a != b {
			return errors.New("USB_NATIVE_PROFILE_RECOVERY_NODE_CHANGED")
		}
		return nil
	}, ctx.Err)
}

// ReadOwnedPrivateProfileForRestoreNative is recovery-only. It deliberately
// needs no active address: earlier restoration may have already removed it.
// The callback must fresh-check the exact protected original receipt/owner;
// the native gate then independently proves mapping and healthy Wintun driver.
func ReadOwnedPrivateProfileForRestoreNative(ctx context.Context, p OwnedProfileRecoveryIdentity, verifyOwnedOriginal func() error, logger *log.Logger) (guid string, category uint32, err error) {
	verify := func() error { return verifyProfileRecoveryIdentity(ctx, p, verifyOwnedOriginal) }
	err = nativeStep(logger, "private_profile_recovery_read", func() error {
		return wincom.WithApartment(func() error {
			n, g, c, e := nlmReadVerified(ctx, p.GUID, verify)
			defer nlmRelease(n)
			guid, category = g, c
			return e
		})
	})
	return
}

// RestoreOwnedPrivateProfileNative can only restore the protected expected
// network's original public/private category. It never sets new profile policy
// or returns a normal rule/Ready proof, and refuses domain/shared/unknown state.
func RestoreOwnedPrivateProfileNative(ctx context.Context, p OwnedProfileRecoveryIdentity, verifyOwnedOriginal func() error, expectedNetworkGUID string, originalCategory uint32, logger *log.Logger) error {
	if !guidPattern.MatchString(expectedNetworkGUID) || originalCategory > 1 {
		return errors.New("USB_NATIVE_PROFILE_ORIGINAL_INVALID")
	}
	owned := uint32(1)
	return applyPrivateProfileVerified(ctx, p.GUID, func() error { return verifyProfileRecoveryIdentity(ctx, p, verifyOwnedOriginal) }, expectedNetworkGUID, originalCategory, &owned, true, logger)
}

// VerifyOwnedWintunRecoveryIdentityNative is an identity-only restoration gate.
// It provides no address/Ready/firewall authorization and never changes policy.
func VerifyOwnedWintunRecoveryIdentityNative(ctx context.Context, p OwnedProfileRecoveryIdentity, verifyOwnedOriginal func() error) error {
	return verifyProfileRecoveryIdentity(ctx, p, verifyOwnedOriginal)
}
