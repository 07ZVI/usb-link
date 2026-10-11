//go:build windows && amd64

package usbhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/wintun"
	"unsafe"
)

// Interface configuration is restored only to the exact completed current
// mapping. No successful-Create inference or conversion to a v1 address intent
// participates in this explicit uninstall transaction.
func restorePersistentHostFactory(ctx context.Context, dir string, p journal, d *wintun.Device) error {
	v, found, e := readPersistentFactory(dir)
	if e != nil || !found || v.State != "ready" || v.Source != p {
		return errors.New("USB_HOST_FACTORY_RESTORE_BINDING_UNPROVEN")
	}
	requested, e := interfaceconfig.PersistentRestoreRequested(dir)
	if e != nil || !requested {
		return errors.New("USB_HOST_FACTORY_RESTORE_INTENT_REQUIRED")
	}
	original, found, e := interfaceconfig.ReadPersistentOriginalSnapshotForRestore(dir, "host")
	if e != nil || !found || original != v.Original {
		return errors.New("USB_HOST_FACTORY_RESTORE_ORIGINAL_CHANGED")
	}
	if e = factoryRecordCurrent(dir, v); e != nil {
		return e
	}
	if d.Index != p.Index || d.LUID != p.LUID || factoryNative(v, p.Index, p.LUID) != nil {
		return errors.New("USB_HOST_FACTORY_RESTORE_HANDLE_UNPROVEN")
	}
	restoring := v
	restoring.State = "restoring"
	if e = writePersistentFactory(dir, restoring, &v); e != nil {
		return e
	}
	if e = finishPersistentHostOriginalRestore(ctx, dir, restoring); e != nil {
		return e
	}
	d.Close() // joined exact handle; asynchronous PnP retirement stays checkpointed.
	stopped, found, e := readPersistentFactory(dir)
	if e != nil || !found {
		return errors.New("USB_HOST_FACTORY_RESTORE_BINDING_UNPROVEN")
	}
	return finishPersistentHostRemoval(ctx, dir, stopped)
}
func freshRestoringHost(dir string, v persistentFactory) (journal, error) {
	if e := factoryRecordCurrent(dir, v); e != nil {
		return journal{}, e
	}
	r, present, e := findHost()
	if e != nil || !present || r.InterfaceLuid != v.Source.LUID {
		return journal{}, errors.New("USB_HOST_FACTORY_RESTORE_MAPPING_CHANGED")
	}
	if e = factoryNative(v, r.InterfaceIndex, r.InterfaceLuid); e != nil {
		return journal{}, e
	}
	p := v.Source
	p.Index = r.InterfaceIndex
	return p, nil
}
func factoryAllAddressesAbsent(index uint32, luid uint64) error {
	var t *windows.MibUnicastIpAddressTable
	if windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &t) != nil || t == nil {
		return errors.New("USB_HOST_FACTORY_ADDRESS_TABLE_UNREADABLE")
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	if t.NumEntries > 65536 {
		return errors.New("USB_HOST_FACTORY_ADDRESS_TABLE_UNREADABLE")
	}
	for _, a := range unsafe.Slice(&t.Table[0], int(t.NumEntries)) {
		if a.InterfaceLuid == luid || (index != 0 && a.InterfaceIndex == index) {
			return errors.New("USB_HOST_FACTORY_FOREIGN_ADDRESS_REMAINS")
		}
	}
	var routes *windows.MibIpForwardTable2
	if windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes) != nil || routes == nil {
		return errors.New("USB_HOST_FACTORY_ROUTE_TABLE_UNREADABLE")
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	if routes.NumEntries > 65536 {
		return errors.New("USB_HOST_FACTORY_ROUTE_TABLE_UNREADABLE")
	}
	for _, r := range unsafe.Slice(&routes.Table[0], int(routes.NumEntries)) {
		if r.InterfaceLuid == luid || (index != 0 && r.InterfaceIndex == index) {
			return errors.New("USB_HOST_FACTORY_FOREIGN_ROUTE_REMAINS")
		}
	}
	return nil
}
func factoryOriginalValuesRestored(ctx context.Context, dir string, v persistentFactory, p journal) error {
	if e := factoryRecordCurrent(dir, v); e != nil {
		return e
	}
	if e := factoryNative(v, p.Index, p.LUID); e != nil {
		return e
	}
	if e := factoryAllAddressesAbsent(p.Index, p.LUID); e != nil {
		return e
	}
	f := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if windows.GetIpInterfaceEntry(&f) != nil || f.InterfaceIndex != p.Index || f.NlMtu != v.Original.OriginalMTU || !factoryRestoredFlags(v, f) {
		return errors.New("USB_HOST_FACTORY_RESTORED_INTERFACE_CHANGED")
	}
	owner := func() error {
		if e := factoryRecordCurrent(dir, v); e != nil {
			return e
		}
		return factoryNative(v, p.Index, p.LUID)
	}
	g, n, e := factoryProfile(hostScope(p), owner).Read(ctx)
	if e != nil || !strings.EqualFold(g, v.Original.NetworkGUID) || n != v.Original.OriginalCategory {
		return errors.New("USB_HOST_FACTORY_RESTORED_PROFILE_CHANGED")
	}
	return nil
}
func finishPersistentHostOriginalRestore(ctx context.Context, dir string, v persistentFactory) (result error) {
	if e := verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	endPhase := persistentFactoryPhase("restore_originals")
	defer func() { endPhase(result) }()
	if v.State != "restoring" {
		return errors.New("USB_HOST_FACTORY_RESTORE_PHASE_INVALID")
	}
	requested, e := interfaceconfig.PersistentRestoreRequested(dir)
	if e != nil || !requested {
		return errors.New("USB_HOST_FACTORY_RESTORE_INTENT_REQUIRED")
	}
	p, e := freshRestoringHost(dir, v)
	if e != nil {
		return e
	}
	owner := func() error {
		if e := verifyPersistentRestoreOwner(ctx); e != nil {
			return e
		}
		q, e := freshRestoringHost(dir, v)
		if e != nil || q != p {
			return errors.New("USB_HOST_FACTORY_RESTORE_MAPPING_CHANGED")
		}
		return nil
	}
	// DAD must be restored while the complete original Store still exists.
	dad, hasDad, e := interfaceconfig.ReadDADOriginalScopeForRestore(dir, "host")
	if e != nil {
		return e
	}
	if hasDad && dad != hostScope(p) {
		if dad.Role != "host" || dad.GUID != p.GUID || dad.LUID != p.LUID {
			return errors.New("USB_HOST_FACTORY_RESTORE_DAD_SOURCE_CHANGED")
		}
		verifyOriginal := func(actual interfaceconfig.Scope) error {
			if actual != dad {
				return errors.New("USB_HOST_FACTORY_RESTORE_DAD_SOURCE_CHANGED")
			}
			return owner()
		}
		if e = interfaceconfig.RestoreDADZeroForOwnedProjectionForRestore(ctx, dir, dad, hostScope(p), v.OriginalSHA256, verifyOriginal); e != nil {
			return e
		}
	} else if e = interfaceconfig.RestoreDADZero(ctx, dir, hostScope(p), owner); e != nil {
		return e
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
	// Any remaining ActiveStore row must still be the exact recorded creation.
	// An infinite row with a different Created value is not an adoption grant.
	if e = owner(); e != nil {
		return e
	}
	if e = remove(p); e != nil {
		return e
	}
	if e = owner(); e != nil {
		return e
	}
	return interfaceconfig.WithHostOriginalsRestored(dir, func() error {
		if e := factoryOriginalValuesRestored(ctx, dir, v, p); e != nil {
			return e
		}
		next := v
		next.State = "stopped"
		return writePersistentFactory(dir, next, &v)
	})
}
func factoryRemovalSource(dir string, v persistentFactory) (journal, bool, error) {
	if e := factoryRecordCurrent(dir, v); e != nil {
		return journal{}, false, e
	}
	r, present, e := findHost()
	if e != nil || !present || r.InterfaceLuid != factoryRemovalLUID(v) {
		return journal{}, false, errors.New("USB_HOST_FACTORY_REMOVAL_MAPPING_UNPROVEN")
	}
	instance, np, e := netconfig.CaptureSharedHostClosingNative(r.InterfaceIndex, r.InterfaceLuid)
	if e != nil || !strings.EqualFold(instance, v.Instance) {
		return journal{}, false, errors.New("USB_HOST_FACTORY_REMOVAL_NODE_UNPROVEN")
	}
	p := v.Source
	p.Index = r.InterfaceIndex
	p.LUID = r.InterfaceLuid
	if factoryRestoreMappedPhase(v.State) {
		p.Created = 0
		p.Planned = 0
	}
	if e = factoryAllAddressesAbsent(p.Index, p.LUID); e != nil {
		return journal{}, false, e
	}
	f := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if windows.GetIpInterfaceEntry(&f) != nil || f.InterfaceIndex != p.Index || f.NlMtu != v.Original.OriginalMTU || !factoryRestoredFlags(v, f) {
		return journal{}, false, errors.New("USB_HOST_FACTORY_REMOVAL_CONFIG_CHANGED")
	}
	return p, np, nil
}
func finishPersistentHostRemoval(ctx context.Context, dir string, v persistentFactory) (result error) {
	if e := verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	endPhase := persistentFactoryPhase("remove_exact")
	defer func() { endPhase(result) }()
	if v.State == "removed" || v.State == "removing" || v.State == "removal_unknown" || v.State == "removal_restart" || v.State == "restore_removed" || v.State == "restore_removing" || v.State == "restore_removal_unknown" || v.State == "restore_removal_restart" {
		return finishPersistentHostRemoved(ctx, dir, v)
	}
	if v.State != "stopped" && v.State != "restore_stopped" {
		return errors.New("USB_HOST_FACTORY_REMOVAL_PHASE_INVALID")
	}
	return interfaceconfig.WithHostOriginalsRestored(dir, func() error {
		absent, e := netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
		if e != nil {
			return e
		}
		if absent {
			if e = factoryRemovalAddressesAbsent(v); e != nil {
				return e
			}
			// There was no mutation in this stack. Preserve a removed proof before
			// deleting either file so a crash can resume the two-file final checkpoint.
			if e = verifyPersistentRestoreOwner(ctx); e != nil {
				return e
			}
			removing := v
			removing.State = factoryRemovalPhase(v, "removing")
			removing.Attempt = makeFactoryNonce()
			removing.Ticks = systemTicks()
			if removing.Attempt == "" || removing.Ticks == 0 {
				return errors.New("USB_HOST_FACTORY_REMOVAL_COUNTER_UNPROVEN")
			}
			if e = writePersistentFactory(dir, removing, &v); e != nil {
				return e
			}
			if e = verifyPersistentRestoreOwner(ctx); e != nil {
				return e
			}
			removed := removing
			removed.State = factoryRemovalPhase(removing, "removed")
			if e = writePersistentFactory(dir, removed, &removing); e != nil {
				return e
			}
			return clearPersistentFactoryRestored(ctx, dir, removed)
		}
		p, np, e := factoryRemovalSource(dir, v)
		if e != nil {
			return e
		}
		var pending persistentFactory
		nativeRemove := netconfig.RemoveVerifiedSharedHostNative
		if np {
			nativeRemove = netconfig.RemoveVerifiedNonpresentSharedHostNative
		}
		if e = verifyPersistentRestoreOwner(ctx); e != nil {
			return e
		}
		result, removeErr := nativeRemove(ctx, p.Index, p.LUID, func(instance string) error {
			if e := verifyPersistentRestoreOwner(ctx); e != nil {
				return e
			}
			if !strings.EqualFold(instance, v.Instance) {
				return errors.New("USB_HOST_FACTORY_REMOVAL_NODE_CHANGED")
			}
			check, checkNP, e := factoryRemovalSource(dir, v)
			if e != nil || check != p || checkNP != np {
				return errors.New("USB_HOST_FACTORY_REMOVAL_SOURCE_CHANGED")
			}
			pending = v
			pending.State = factoryRemovalPhase(v, "removing")
			pending.Attempt = makeFactoryNonce()
			pending.Ticks = systemTicks()
			if pending.Attempt == "" || pending.Ticks == 0 {
				return errors.New("USB_HOST_FACTORY_REMOVAL_COUNTER_UNPROVEN")
			}
			if e = verifyPersistentRestoreOwner(ctx); e != nil {
				return e
			}
			if e = writePersistentFactory(dir, pending, &v); e != nil {
				return e
			}
			if e = verifyPersistentRestoreOwner(ctx); e != nil {
				return e
			}
			check, checkNP, e = factoryRemovalSource(dir, pending)
			if e != nil || check != p || checkNP != np {
				return errors.New("USB_HOST_FACTORY_REMOVAL_SOURCE_CHANGED")
			}
			return nil
		})
		if e = verifyPersistentRestoreOwner(ctx); e != nil {
			return e
		}
		if pending.Ticks == 0 {
			return removeErr
		}
		next := pending
		if removeErr != nil || !result.Attempted || !result.FlagsReadable || result.RestartRequired || !result.AbsenceVerified {
			next.State = factoryRemovalPhase(pending, "removal_unknown")
			if result.RestartRequired {
				next.State = factoryRemovalPhase(pending, "removal_restart")
			}
			if e = writePersistentFactory(dir, next, &pending); e != nil {
				return e
			}
			if removeErr != nil {
				return removeErr
			}
			return errors.New("USB_HOST_FACTORY_REMOVAL_INCOMPLETE")
		}
		next.State = factoryRemovalPhase(pending, "removed")
		if e = writePersistentFactory(dir, next, &pending); e != nil {
			return e
		}
		return clearPersistentFactoryRestored(ctx, dir, next)
	})
}
func makeFactoryNonce() string {
	var n [16]byte
	if _, e := rand.Read(n[:]); e != nil {
		return ""
	}
	return hex.EncodeToString(n[:])
}
func finishPersistentHostRemoved(ctx context.Context, dir string, v persistentFactory) error {
	if e := verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	return interfaceconfig.WithHostOriginalsRestored(dir, func() error {
		absent, e := netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
		if e != nil || !absent {
			return errors.New("USB_HOST_FACTORY_REMOVAL_ABSENCE_UNPROVEN")
		}
		if e = factoryRemovalAddressesAbsent(v); e != nil {
			return e
		}
		if v.State != "removed" && v.State != "restore_removed" {
			if e = persistentFactoryUnknownAbsent(v, systemTicks(), true, 0, 0); e != nil {
				return e
			}
			if e = verifyPersistentRestoreOwner(ctx); e != nil {
				return e
			}
			n := v
			n.State = factoryRemovalPhase(v, "removed")
			if e = writePersistentFactory(dir, n, &v); e != nil {
				return e
			}
			v = n
		}
		return clearPersistentFactoryRestored(ctx, dir, v)
	})
}
func clearPersistentFactoryRestored(ctx context.Context, dir string, v persistentFactory) error {
	if e := verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	if e := factoryNoLegacyIntent(dir); e != nil {
		return e
	}
	got, found, e := readPersistentFactory(dir)
	if e != nil || !found || got != v || (v.State != "removed" && v.State != "restore_removed") {
		return errors.New("USB_HOST_FACTORY_RESTORED_RECORD_CHANGED")
	}
	absent, e := netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
	if e != nil || !absent {
		return errors.New("USB_HOST_FACTORY_REMOVAL_ABSENCE_UNPROVEN")
	}
	if e = factoryRemovalAddressesAbsent(v); e != nil {
		return e
	}
	b, found, e := readFactoryProtected(dir, "usb-host-address.json", 2048)
	if e != nil {
		return e
	}
	if e = persistentFactoryFinalJournalGate(v, b, found); e != nil {
		return e
	}
	if found {
		if e = factoryRemovalAddressesAbsent(v); e != nil {
			return e
		}
		if e = verifyPersistentRestoreOwner(ctx); e != nil {
			return e
		}
		if e = os.Remove(filepath.Join(dir, "usb-host-address.json")); e != nil {
			return errors.New("USB_HOST_FACTORY_JOURNAL_REMOVE_FAILED")
		}
	}
	_, found, e = readFactoryProtected(dir, "usb-host-address.json", 2048)
	if e != nil || found {
		return errors.New("USB_HOST_FACTORY_JOURNAL_ABSENCE_UNPROVEN")
	}
	got, found, e = readPersistentFactory(dir)
	if e != nil || !found || got != v {
		return errors.New("USB_HOST_FACTORY_RESTORED_RECORD_CHANGED")
	}
	absent, e = netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
	if e != nil || !absent {
		return errors.New("USB_HOST_FACTORY_REMOVAL_ABSENCE_UNPROVEN")
	}
	if e = factoryRemovalAddressesAbsent(v); e != nil {
		return e
	}
	if e = verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(dir, persistentFactoryFile)); e != nil {
		return errors.New("USB_HOST_FACTORY_RECORD_REMOVE_FAILED")
	}
	if e = verifyPersistentRestoreOwner(ctx); e != nil {
		return e
	}
	_, found, e = readPersistentFactory(dir)
	if e != nil || found {
		return errors.New("USB_HOST_FACTORY_RECORD_ABSENCE_UNPROVEN")
	}
	return nil
}

func beginPersistentHostOriginalRestore(dir string, v persistentFactory) (persistentFactory, error) {
	if v.State != "ready" && v.State != "closed" {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RESTORE_PHASE_INVALID")
	}
	requested, e := interfaceconfig.PersistentRestoreRequested(dir)
	if e != nil || !requested {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RESTORE_INTENT_REQUIRED")
	}
	original, found, e := interfaceconfig.ReadPersistentOriginalSnapshotForRestore(dir, "host")
	if e != nil || !found || original != v.Original {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RESTORE_ORIGINAL_CHANGED")
	}
	if _, e = freshRestoringHost(dir, v); e != nil {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RESTORE_LIVE_MAPPING_REQUIRED")
	}
	next := v
	next.State = "restoring"
	if e = writePersistentFactory(dir, next, &v); e != nil {
		return persistentFactory{}, e
	}
	return next, nil
}

func factoryRestoredFlags(v persistentFactory, f windows.MibIpInterfaceRow) bool {
	if factoryRestoreMappedPhase(v.State) {
		// No ordinary network setup is permitted in a restore-only creator. An
		// external enabling of forwarding/weak host behavior is not adopted.
		return f.ForwardingEnabled == 0 && f.WeakHostSend == 0 && f.WeakHostReceive == 0
	}
	return f.ForwardingEnabled == 1 && f.WeakHostSend == 1 && f.WeakHostReceive == 1
}
func factoryRemovalAddressesAbsent(v persistentFactory) error {
	if e := factoryAllAddressesAbsent(0, v.Source.LUID); e != nil {
		return e
	}
	if factoryRestoreMappedPhase(v.State) && v.MappedLUID != v.Source.LUID {
		return factoryAllAddressesAbsent(0, v.MappedLUID)
	}
	return nil
}
