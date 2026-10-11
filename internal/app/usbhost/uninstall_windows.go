//go:build windows && amd64

package usbhost

import (
	"context"
	"errors"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
)

func HostUninstallFactoryRequired(dir string) (bool, error) {
	hostOperationMu.Lock()
	defer hostOperationMu.Unlock()
	_, found, e := readPersistentFactory(dir)
	if e != nil {
		return false, e
	}
	if found {
		return true, nil
	}
	_, persistent, e := interfaceconfig.ReadPersistentOriginalSnapshotForRestore(dir, "host")
	if e != nil {
		return false, e
	}
	_, dad, e := interfaceconfig.ReadDADOriginalScopeForRestore(dir, "host")
	if e != nil {
		return false, e
	}
	return persistent || dad, nil
}

// No-obligation legacy/default-OFF installs never require a missing factory.
// A present original without its factory remains an error, not an adoption.
func RestoreOwnedHostForUninstall(ctx context.Context, dir, dll string, verifyInstalledOwner func() error) error {
	if ctx == nil || verifyInstalledOwner == nil || verifyInstalledOwner() != nil {
		return errors.New("USB_HOST_UNINSTALL_OWNER_REQUIRED")
	}
	needed, e := HostUninstallFactoryRequired(dir)
	if e != nil {
		return e
	}
	// Ordinary Recover grants no creator. It may finish an exact live restoration
	// or durable removal phase; an absent original mapping needs the explicit API.
	recoveryErr := recoverHostForUninstall(ctx, dir, verifyInstalledOwner)
	if recoveryErr != nil && needed {
		if e = RestorePersistentHostFactoryForUninstallVerified(ctx, dir, dll, verifyInstalledOwner); e != nil {
			return errors.Join(recoveryErr, e)
		}
	} else if recoveryErr != nil {
		return recoveryErr
	}
	if e = verifyInstalledOwner(); e != nil {
		return e
	}
	return ConfirmHostUninstallComplete(dir)
}

func recoverHostForUninstall(ctx context.Context, dir string, verifyInstalledOwner func() error) error {
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return e
	}
	defer release()
	if !hostOperationMu.TryLock() {
		return errors.New("USB_HOST_UNINSTALL_OPERATION_BUSY")
	}
	defer hostOperationMu.Unlock()
	live.Lock()
	active := live.p != (journal{})
	live.Unlock()
	if active {
		return errors.New("USB_HOST_UNINSTALL_LIVE_SESSION")
	}
	if e = verifyInstalledOwner(); e != nil {
		return e
	}
	v, found, e := readPersistentFactory(dir)
	if e != nil {
		return e
	}
	if found {
		return recoverPersistentHostFactory(context.WithValue(ctx, persistentRestoreOwnerKey{}, verifyInstalledOwner), dir, v)
	}
	return recoverUnlocked(dir) // legacy receipt-only cleanup; never a creator.
}

func ConfirmHostUninstallComplete(dir string) error {
	hostOperationMu.Lock()
	defer hostOperationMu.Unlock()
	for _, name := range []string{persistentFactoryFile, removalFile, recreateFile, "usb-host-address.json"} {
		_, found, e := readFactoryProtected(dir, name, 8192)
		if e != nil {
			return e
		}
		if found {
			return errors.New("USB_HOST_UNINSTALL_OWNERSHIP_REMAINS")
		}
	}
	_, found, e := interfaceconfig.ReadPersistentOriginalSnapshotForRestore(dir, "host")
	if e != nil {
		return e
	}
	if found {
		return errors.New("USB_HOST_UNINSTALL_ORIGINAL_REMAINS")
	}
	_, found, e = interfaceconfig.ReadDADOriginalScopeForRestore(dir, "host")
	if e != nil {
		return e
	}
	if found {
		return errors.New("USB_HOST_UNINSTALL_DAD_REMAINS")
	}
	absent, e := netconfig.ConfirmSharedHostAbsentNative()
	if e != nil || !absent {
		return errors.New("USB_HOST_UNINSTALL_NATIVE_ABSENCE_UNPROVEN")
	}
	return nil
}
