//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
)

// Read-only planning never grants a factory call. The restore entry independently
// repeats all protected originals, phase and native source proofs.
func MacUninstallFactoryRequired(dir string) (bool, error) {
	finish, e := lockConfig()
	if e != nil {
		return false, e
	}
	defer finish()
	_, found, e := readSecondaryBinding(dir)
	if e != nil {
		return false, e
	}
	s, has, e := readConfigReceiptFile(dir)
	if e != nil {
		return false, e
	}
	if found {
		return true, nil
	}
	if has {
		for _, o := range s.Persistent {
			if o.Scope.Role == "mac" {
				return true, nil
			}
		}
		for _, o := range s.DAD {
			if o.Scope.Role == "mac" {
				return true, nil
			}
		}
	}
	return false, nil
}

func RestoreOwnedMacForUninstall(ctx context.Context, dir, dll string, verifyInstalledOwner func() error) error {
	if ctx == nil || verifyInstalledOwner == nil || verifyInstalledOwner() != nil {
		return errors.New("USB_MAC_UNINSTALL_OWNER_REQUIRED")
	}
	needed, e := MacUninstallFactoryRequired(dir)
	if e != nil {
		return e
	}
	if !needed {
		return ConfirmMacUninstallComplete(dir)
	}
	if e = RestorePersistentMacFactoryWithDLL(ctx, dir, dll, verifyInstalledOwner); e != nil {
		return e
	}
	if e = verifyInstalledOwner(); e != nil {
		return e
	}
	return ConfirmMacUninstallComplete(dir)
}

// A consumed Store does not consume a surviving factory checkpoint. No missing
// original is substituted and every unknown factory phase blocks file removal.
func ConfirmMacUninstallComplete(dir string) error {
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	_, found, e := readSecondaryBinding(dir)
	if e != nil {
		return e
	}
	if found {
		return errors.New("USB_MAC_UNINSTALL_FACTORY_REMAINS")
	}
	s, has, e := readConfigReceiptFile(dir)
	if e != nil {
		return e
	}
	if has {
		for _, o := range s.Persistent {
			if o.Scope.Role == "mac" {
				return errors.New("USB_MAC_UNINSTALL_ORIGINAL_REMAINS")
			}
		}
		for _, o := range s.DAD {
			if o.Scope.Role == "mac" {
				return errors.New("USB_MAC_UNINSTALL_DAD_REMAINS")
			}
		}
	}
	return nil
}
