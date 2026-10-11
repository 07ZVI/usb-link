//go:build windows && amd64

package usbhost

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
)

// RestorePersistentHostFactoryForUninstall is a local uninstall-only entry.
// The caller must obtain dllPath from the receipt-verified built-in archive;
// RPC, environment, registry and diagnostic-selected paths are not permitted.
// The parent must first prove its bound core/bridge processes are stopped and
// all session leases drained; a Local topology mutex is not cross-session proof.
// Ordinary Recover deliberately has no creator source and never invokes this.
// This API publishes no session/proof, does not call ordinary Apply, and never
// replaces the immutable original or complete pre-uninstall Source journal.
func RestorePersistentHostFactoryForUninstall(ctx context.Context, dir, dllPath string) error {
	return errors.New("USB_HOST_FACTORY_RESTORE_INSTALLED_OWNER_REQUIRED")
}

type persistentRestoreOwnerKey struct{}

// RestorePersistentHostFactoryForUninstallVerified requires the uninstall
// coordinator's fresh installed-owner/stopped-process proof throughout every
// durable or native mutation. The callback must not re-enter interfaceconfig.
func RestorePersistentHostFactoryForUninstallVerified(ctx context.Context, dir, dllPath string, verifyInstalledOwner func() error) error {
	if ctx == nil || verifyInstalledOwner == nil {
		return errors.New("USB_HOST_FACTORY_RESTORE_INSTALLED_OWNER_REQUIRED")
	}
	ctx = context.WithValue(ctx, persistentRestoreOwnerKey{}, verifyInstalledOwner)
	if e := verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	return restorePersistentHostFactoryForUninstallWithOwner(ctx, dir, dllPath)
}
func verifyPersistentRestoreOwner(ctx context.Context) error {
	if ctx == nil {
		return errors.New("USB_HOST_FACTORY_RESTORE_CONTEXT_REQUIRED")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if f, ok := ctx.Value(persistentRestoreOwnerKey{}).(func() error); ok {
		if f == nil {
			return errors.New("USB_HOST_FACTORY_RESTORE_INSTALLED_OWNER_REQUIRED")
		}
		return f()
	}
	return nil // Ordinary Recover keeps its existing receipt-only cleanup scope.
}
func restorePersistentHostFactoryForUninstallWithOwner(ctx context.Context, dir, dllPath string) error {
	if ctx == nil {
		return errors.New("USB_HOST_FACTORY_RESTORE_CONTEXT_REQUIRED")
	}
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return e
	}
	defer release()
	// Do not hold the topology lease while waiting for an in-flight Start
	// that may itself need that lease. The parent retries only after drain.
	if !hostOperationMu.TryLock() {
		return errors.New("USB_HOST_FACTORY_RESTORE_OPERATION_BUSY")
	}
	defer hostOperationMu.Unlock()
	live.Lock()
	active := live.p != (journal{})
	live.Unlock()
	if active {
		return errors.New("USB_HOST_FACTORY_RESTORE_LIVE_SESSION")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	v, found, e := readPersistentFactory(dir)
	if e != nil || !found {
		return errors.New("USB_HOST_FACTORY_RESTORE_BINDING_UNPROVEN")
	}
	if e = restoreFactoryIntent(dir); e != nil {
		return e
	}
	if factoryRestoreMappedPhase(v.State) || v.State == "restore_attempt" {
		if e = recoverPersistentRestoreFactory(ctx, dir, v); e != nil {
			return e
		}
		v, found, e = readPersistentFactory(dir)
		if e != nil {
			return e
		}
		if !found {
			return nil
		}
	}
	if v.State != "ready" && v.State != "closed" && v.State != "restoring" {
		return errors.New("USB_HOST_FACTORY_RESTORE_PHASE_INVALID")
	}
	if e = restoreFactoryOriginal(dir, v); e != nil {
		return e
	}
	if e = verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	if e = restoreFactorySource(dir, v); e != nil {
		return e
	}
	pin, e := netconfig.PinVerifiedWintunNative(dllPath, log.New(os.Stderr, "USB host restore factory: ", 0))
	if e != nil {
		return e
	}
	defer pin.Close()
	// Re-read the exact source after DLL pin/loading, then persist the attempt
	// before the first possible native call. Close and Create remain joined.
	if e = restoreFactorySource(dir, v); e != nil {
		return e
	}
	attempt := v
	attempt.State = "restore_attempt"
	attempt.Attempt = makeFactoryNonce()
	attempt.Ticks = systemTicks()
	if attempt.Attempt == "" || attempt.Ticks == 0 {
		return errors.New("USB_HOST_FACTORY_RESTORE_COUNTER_UNPROVEN")
	}
	if e = verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	if e = writePersistentFactory(dir, attempt, &v); e != nil {
		return e
	}
	before := func() error {
		if e := verifyPersistentRestoreOwner(ctx); e != nil {
			return e
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		return restoreFactorySource(dir, attempt)
	}
	observation := wintun.OwnedCreateObservation{}
	d, e := wintun.CreateOwnedNonpresentHost(dllPath, before, &observation)
	if e != nil {
		// Even a known no-call retains the attempt if fresh source/intent/original
		// proof fails. Unknown results never authorize another creator in this boot.
		if !observation.Called && before() == nil {
			closed := attempt
			closed.State = "closed"
			closed.Attempt = ""
			closed.Ticks = 0
			if ce := writePersistentFactory(dir, closed, &attempt); ce != nil {
				return ce
			}
		}
		return e
	}
	defer d.Close()
	if !observation.Called || !observation.Returned || !observation.Succeeded || !observation.FixedGUIDVerified || observation.Index != d.Index || observation.LUID != d.LUID || !d.FactoryHandleHeld() || factoryNative(attempt, d.Index, d.LUID) != nil {
		return errors.New("USB_HOST_FACTORY_RESTORE_RETURN_UNPROVEN")
	}
	if e = restoreFactoryOriginal(dir, attempt); e != nil {
		return e
	}
	if e = factoryRecordCurrent(dir, attempt); e != nil {
		return e
	}
	mapped := attempt
	mapped.State = "restore_mapped"
	mapped.MappedIndex = d.Index
	mapped.MappedLUID = d.LUID
	if e = verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	if e = writePersistentFactory(dir, mapped, &attempt); e != nil {
		return e
	}
	if e = finishPersistentRestoreFactoryOriginals(ctx, dir, mapped, d); e != nil {
		return e
	}
	d.Close() // exact joined creator; subsequent PnP retirement is not guessed.
	stopped, found, e := readPersistentFactory(dir)
	if e != nil || !found {
		return errors.New("USB_HOST_FACTORY_RESTORE_BINDING_UNPROVEN")
	}
	return finishPersistentHostRemoval(ctx, dir, stopped)
}
func restoreFactoryIntent(dir string) error {
	if e := factoryNoLegacyIntent(dir); e != nil {
		return e
	}
	requested, e := interfaceconfig.PersistentRestoreRequested(dir)
	if e != nil || !requested {
		return errors.New("USB_HOST_FACTORY_RESTORE_INTENT_REQUIRED")
	}
	return nil
}
func restoreFactoryOriginal(dir string, v persistentFactory) error {
	if e := restoreFactoryIntent(dir); e != nil {
		return e
	}
	original, found, e := interfaceconfig.ReadPersistentOriginalSnapshotForRestore(dir, "host")
	if e != nil || !found || original != v.Original {
		return errors.New("USB_HOST_FACTORY_RESTORE_ORIGINAL_CHANGED")
	}
	return factoryRecordCurrent(dir, v)
}
func restoreFactorySource(dir string, v persistentFactory) error {
	if e := restoreFactoryOriginal(dir, v); e != nil {
		return e
	}
	if e := netconfig.VerifySharedHostFactorySourceNative(v.Source.Index, v.Source.LUID, v.Instance); e != nil {
		return e
	}
	// IPv6 or residual routes are not discarded as part of a fixed-GUID guess.
	if e := factoryAllAddressesAbsent(0, v.Source.LUID); e != nil {
		return e
	}
	return factoryRecordCurrent(dir, v)
}
func freshRestoringFactoryMapping(dir string, v persistentFactory) (journal, error) {
	if v.State != "restore_mapped" && v.State != "restore_stopped" {
		return journal{}, errors.New("USB_HOST_FACTORY_RESTORE_MAPPING_PHASE_INVALID")
	}
	if e := factoryRecordCurrent(dir, v); e != nil {
		return journal{}, e
	}
	r, present, e := findHost()
	if e != nil || !present || r.InterfaceLuid != v.MappedLUID {
		return journal{}, errors.New("USB_HOST_FACTORY_RESTORE_RETURN_MAPPING_CHANGED")
	}
	if e = factoryNative(v, r.InterfaceIndex, r.InterfaceLuid); e != nil {
		return journal{}, e
	}
	p := v.Source
	p.Index = r.InterfaceIndex
	p.LUID = r.InterfaceLuid
	// An old creation timestamp has no ownership meaning on the new mapping.
	p.Created = 0
	p.Planned = 0
	return p, nil
}
func finishPersistentRestoreFactoryOriginals(ctx context.Context, dir string, v persistentFactory, d *wintun.Device) error {
	if v.State != "restore_mapped" || d == nil || !d.FactoryHandleHeld() || d.Index != v.MappedIndex || d.LUID != v.MappedLUID {
		return errors.New("USB_HOST_FACTORY_RESTORE_HELD_RETURN_REQUIRED")
	}
	if e := restoreFactoryIntent(dir); e != nil {
		return e
	}
	p, e := freshRestoringFactoryMapping(dir, v)
	if e != nil {
		return e
	}
	owner := func() error {
		if e := verifyPersistentRestoreOwner(ctx); e != nil {
			return e
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if !d.FactoryHandleHeld() || d.Index != v.MappedIndex || d.LUID != v.MappedLUID {
			return errors.New("USB_HOST_FACTORY_RESTORE_HELD_RETURN_REQUIRED")
		}
		q, e := freshRestoringFactoryMapping(dir, v)
		if e != nil {
			return e
		}
		if q != p {
			return errors.New("USB_HOST_FACTORY_RESTORE_RETURN_MAPPING_CHANGED")
		}
		return nil
	}
	// Do not enable ordinary bridge flags solely to satisfy an old ready gate.
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if windows.GetIpInterfaceEntry(&row) != nil || row.InterfaceIndex != p.Index || !factoryRestoredFlags(v, row) {
		return errors.New("USB_HOST_FACTORY_RESTORE_FRESH_CONFIG_UNPROVEN")
	}
	dad, hasDad, e := interfaceconfig.ReadDADOriginalScopeForRestore(dir, "host")
	if e != nil {
		return e
	}
	if hasDad {
		if dad.Role != "host" || dad.GUID != v.Source.GUID || dad.LUID != v.Source.LUID {
			return errors.New("USB_HOST_FACTORY_RESTORE_DAD_SOURCE_CHANGED")
		}
		verify := func(actual interfaceconfig.Scope) error {
			if actual != dad || actual.LUID != v.Source.LUID {
				return errors.New("USB_HOST_FACTORY_RESTORE_DAD_SOURCE_CHANGED")
			}
			return owner() // no interfaceconfig re-entry while its mutex is held.
		}
		if e = interfaceconfig.RestoreDADZeroForOwnedFactoryForRestore(ctx, dir, dad, hostScope(p), v.OriginalSHA256, verify); e != nil {
			return e
		}
	}
	original, has, e := interfaceconfig.ReadPersistentOriginalSnapshotForRestore(dir, "host")
	if e != nil {
		return e
	}
	if has && original != v.Original {
		return errors.New("USB_HOST_FACTORY_RESTORE_ORIGINAL_CHANGED")
	}
	if e = interfaceconfig.RestorePersistentHost(ctx, dir, hostScope(p), owner, factoryProfile(hostScope(p), owner)); e != nil {
		return e
	}
	// Only the provider's exact saved PersistentStore address was authorized.
	// A remaining ActiveStore row is neither removed nor stamped with old Created.
	return interfaceconfig.WithHostOriginalsRestored(dir, func() error {
		if e := owner(); e != nil {
			return e
		}
		if e := factoryOriginalValuesRestored(ctx, dir, v, p); e != nil {
			return e
		}
		if e := verifyPersistentRestoreOwner(ctx); e != nil {
			return e
		}
		stopped := v
		stopped.State = "restore_stopped"
		return writePersistentFactory(dir, stopped, &v)
	})
}

// No process may recover a held creator from a raw GUID. A persisted successful
// returned mapping permits final read-only original-value completion, or a
// reboot+full-absence retry only while the full original is still unchanged.
func recoverPersistentRestoreFactory(ctx context.Context, dir string, v persistentFactory) error {
	if e := verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	if e := restoreFactoryIntent(dir); e != nil {
		return e
	}
	if factoryRestoreMappedPhase(v.State) && v.State != "restore_mapped" {
		return finishPersistentHostRemoval(ctx, dir, v)
	}
	if v.State != "restore_attempt" && v.State != "restore_mapped" {
		return errors.New("USB_HOST_FACTORY_RESTORE_PHASE_INVALID")
	}
	if e := factoryRecordCurrent(dir, v); e != nil {
		return e
	}
	if v.State == "restore_mapped" {
		e := interfaceconfig.WithHostOriginalsRestored(dir, func() error {
			absent, e := netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
			if e != nil {
				return e
			}
			if absent {
				if e = factoryRemovalAddressesAbsent(v); e != nil {
					return e
				}
			} else {
				p, e := freshRestoringFactoryMapping(dir, v)
				if e != nil {
					return e
				}
				if e = factoryOriginalValuesRestored(ctx, dir, v, p); e != nil {
					return e
				}
			}
			if e := verifyPersistentRestoreOwner(ctx); e != nil {
				return e
			}
			stopped := v
			stopped.State = "restore_stopped"
			return writePersistentFactory(dir, stopped, &v)
		})
		if e == nil {
			stopped, found, e := readPersistentFactory(dir)
			if e != nil || !found {
				return errors.New("USB_HOST_FACTORY_RESTORE_BINDING_UNPROVEN")
			}
			return finishPersistentHostRemoval(ctx, dir, stopped)
		}
	}
	if e := restoreFactoryOriginal(dir, v); e != nil {
		return e
	}
	absent, e := netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
	if e != nil {
		return e
	}
	oldRows, oe := recoveryAddresses(0, v.Source.LUID)
	var newRows []recoveryAddress
	var ne error
	if v.MappedLUID != 0 && v.MappedLUID != v.Source.LUID {
		newRows, ne = recoveryAddresses(0, v.MappedLUID)
	}
	if oe != nil || ne != nil {
		return errors.New("USB_HOST_FACTORY_RESTORE_UNKNOWN_ADDRESS_UNPROVEN")
	}
	if e = persistentFactoryUnknownAbsent(v, systemTicks(), absent, len(oldRows), len(newRows)); e != nil {
		return e
	}
	if e = factoryAllAddressesAbsent(0, v.Source.LUID); e != nil {
		return e
	}
	if v.MappedLUID != 0 {
		if e = factoryAllAddressesAbsent(0, v.MappedLUID); e != nil {
			return e
		}
	}
	// Fresh proof after disk reads precedes the only permitted unknown retry.
	if e = restoreFactoryOriginal(dir, v); e != nil {
		return e
	}
	absent, e = netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
	if e != nil || !absent {
		return errors.New("USB_HOST_FACTORY_RESTORE_UNKNOWN_ABSENCE_UNPROVEN")
	}
	if e = verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	closed := v
	closed.State = "closed"
	closed.Attempt = ""
	closed.Ticks = 0
	closed.MappedIndex = 0
	closed.MappedLUID = 0
	return writePersistentFactory(dir, closed, &v)
}

func factoryNoLegacyIntent(dir string) error {
	_, found, e := readRemovalIntentFile(dir)
	if e != nil {
		return e
	}
	if found {
		return errors.New("USB_HOST_FACTORY_LEGACY_INTENT_CONFLICT")
	}
	_, found, e = readRecreateTransactionFile(dir)
	if e != nil {
		return e
	}
	if found {
		return errors.New("USB_HOST_FACTORY_LEGACY_INTENT_CONFLICT")
	}
	return nil
}
