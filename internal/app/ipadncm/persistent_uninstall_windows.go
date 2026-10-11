//go:build windows && amd64

package ipadncm

import (
	"context"
	"errors"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
)

// RestorePersistentIPadForUninstall accepts only the fixed local grouping
// store supplied by the installed confirmed-uninstall coordinator, after all
// service/session owners are joined. It precedes any grouping/root restart.
// It never creates/rebinds a node and restores with optimization flags OFF.
func RestorePersistentIPadForUninstall(ctx context.Context, dir string) error {
	present, e := ipadConfigurationFilesPresent(dir)
	if e != nil || !present {
		return e
	}
	v, found, e := interfaceconfig.ReadIPadPersistentBinding(dir)
	if e != nil {
		return e
	}
	if !found {
		_, pending, _, e := interfaceconfig.ReadIPadOriginalsState(dir)
		if e != nil {
			return e
		}
		if pending {
			return errors.New("IPAD_UNINSTALL_ORIGINALS_WITHOUT_BINDING")
		}
		return nil
	}
	owner := func() error { return verifyIPadPersistentNative(ctx, v) }
	// Do not publish restore intent from a mere filename/diagnostic observation.
	if e = owner(); e != nil {
		return e
	}
	if e = interfaceconfig.RequestIPadPersistentRestore(dir); e != nil {
		return e
	}
	if e = interfaceconfig.BeginIPadPersistentRestore(ctx, dir, v, owner); e != nil {
		return e
	}
	v.State = "restoring"
	if e = interfaceconfig.RestoreDADZero(ctx, dir, v.Scope, owner); e != nil {
		return e
	}
	if e = interfaceconfig.RestorePersistent(ctx, dir, v.Scope, owner, interfaceconfig.IPadProfileOps(v.Scope, owner, nil)); e != nil {
		return e
	}
	if e = owner(); e != nil {
		return e
	}
	if er := removePeerRoute(v.Plan); er != "" {
		return errors.New(er)
	}
	if er := removeApplicationAddress(v.Plan); er != "" {
		return errors.New(er)
	}
	if er := restoreUSBHostFlags(v.Plan); er != "" {
		return errors.New(er)
	}
	if e = owner(); e != nil {
		return e
	}
	if e = verifyApplicationAddressAbsent(v.Plan); e != nil {
		return e
	}
	return interfaceconfig.FinishIPadPersistentBinding(ctx, dir, v, owner)
}
