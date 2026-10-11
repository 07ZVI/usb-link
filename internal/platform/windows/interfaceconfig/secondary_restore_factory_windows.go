//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
)

// RestorePersistentMacFactoryWithDLL is a no-network, uninstall-only factory
// transaction for an exactly owned closed/absent Mac adapter. The installed
// coordinator supplies its fixed verified DLL path and installed-owner proof;
// neither can come from a remote request. The original remains immutable and
// no restore phase grants Apply, address readiness or firewall authorization.
// Unknown Create phases remain fenced. A disappeared original NLA network is
// not replaced with a different network.
func RestorePersistentMacFactoryWithDLL(ctx context.Context, dir, dll string, verifyInstalledOwner func() error) error {
	if ctx == nil || verifyInstalledOwner == nil {
		return errors.New("USB_MAC_RESTORE_INSTALLED_OWNER_REQUIRED")
	}
	if ctx.Err() != nil || verifyInstalledOwner() != nil {
		return errors.New("USB_MAC_RESTORE_INSTALLED_OWNER_UNPROVEN")
	}
	releaseTopology, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return e
	}
	defer releaseTopology()
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	old, found, e := readSecondaryBinding(dir)
	if e != nil {
		return e
	}
	if !found {
		return macOriginalsRestoredUnlocked(dir)
	}
	if old.State == "restored" {
		return finishMacRestoreBindingUnlocked(ctx, dir, old, verifyInstalledOwner)
	}
	if old.State == "restore_mapped" {
		// The actual returned mapping was durably recorded before any restore.
		// A crash after the final originals checkpoint may finish only after
		// complete native absence; it cannot reopen/adopt a healthy mapping.
		if e = macOriginalsRestoredUnlocked(dir); e != nil {
			return errors.New("USB_MAC_RESTORE_UNKNOWN_FACTORY_PHASE")
		}
		if verifyInstalledOwner() != nil || ctx.Err() != nil {
			return errors.New("USB_MAC_RESTORE_INSTALLED_OWNER_UNPROVEN")
		}
		absent, e := netconfig.MacAdapterAbsentNative()
		if e != nil || !absent || netconfig.VerifyOwnedMacFactorySourceNative(old.CurrentScope.Index, old.CurrentScope.LUID, old.Instance) != nil {
			return errors.New("USB_MAC_RESTORE_FACTORY_ABSENCE_UNPROVEN")
		}
		next := old
		next.State = "restored"
		if e = writeSecondaryBinding(dir, next, &old); e != nil {
			return e
		}
		return finishMacRestoreBindingUnlocked(ctx, dir, next, verifyInstalledOwner)
	}
	if old.State != "closed" && old.State != "ready" {
		return errors.New("USB_MAC_RESTORE_UNKNOWN_FACTORY_PHASE")
	}
	if _, e = exactSecondaryOriginalForMode(dir, old, true); e != nil {
		return e
	}
	source := old.CurrentScope
	pre := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := verifyInstalledOwner(); e != nil {
			return errors.New("USB_MAC_RESTORE_INSTALLED_OWNER_UNPROVEN")
		}
		got, has, e := readSecondaryBinding(dir)
		if e != nil || !has || got != old {
			return errors.New("USB_MAC_RESTORE_SOURCE_CHANGED")
		}
		if _, e = exactSecondaryOriginalForMode(dir, old, true); e != nil {
			return e
		}
		return netconfig.VerifyOwnedMacFactorySourceNative(source.Index, source.LUID, old.Instance)
	}
	if e = pre(); e != nil {
		return e
	}
	if old.State == "ready" {
		closed := old
		closed.State = "closed"
		if e = writeSecondaryBinding(dir, closed, &old); e != nil {
			return e
		}
		old = closed
	}
	pin, e := netconfig.PinVerifiedWintunNative(dll, log.New(os.Stderr, "USB Mac original restore: ", 0))
	if e != nil {
		return e
	}
	defer pin.Close()
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	ticks, _, _ := secondaryTicks.Call()
	if ticks == 0 {
		return errors.New("USB_MAC_RESTORE_TICKS_UNPROVEN")
	}
	attempt := old
	attempt.State, attempt.Mode = "restore_attempt", ""
	attempt.Created = 0
	attempt.Attempt, attempt.Ticks = hex.EncodeToString(nonce[:]), uint64(ticks)
	if e = writeSecondaryBinding(dir, attempt, &old); e != nil {
		return e
	}
	before := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if verifyInstalledOwner() != nil {
			return errors.New("USB_MAC_RESTORE_INSTALLED_OWNER_UNPROVEN")
		}
		got, has, e := readSecondaryBinding(dir)
		if e != nil || !has || got != attempt {
			return errors.New("USB_MAC_RESTORE_ATTEMPT_CHANGED")
		}
		if _, e = exactSecondaryOriginalForMode(dir, attempt, true); e != nil {
			return e
		}
		return netconfig.VerifyOwnedMacFactorySourceNative(source.Index, source.LUID, old.Instance)
	}
	observation := wintun.OwnedCreateObservation{}
	d, e := wintun.CreateOwnedNonpresentMac(dll, before, &observation)
	if e != nil {
		return e // durable unknown attempt is retained, never adopted/replayed.
	}
	defer d.Close() // synchronous factory call completed before the lease releases.
	current := Scope{"mac", MacGUID, d.Index, d.LUID}
	if !observation.Called || !observation.Returned || !observation.Succeeded || !observation.FixedGUIDVerified || !d.FactoryHandleHeld() || validateScope(current) != nil || netconfig.VerifyOwnedMacRecreatedNative(d.Index, d.LUID, old.Instance) != nil {
		return errors.New("USB_MAC_RESTORE_FACTORY_RETURN_UNPROVEN")
	}
	mapped := attempt
	mapped.State, mapped.CurrentScope = "restore_mapped", current
	if e = writeSecondaryBinding(dir, mapped, &attempt); e != nil {
		return e
	}
	verify := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if verifyInstalledOwner() != nil || !d.FactoryHandleHeld() || d.Index != current.Index || d.LUID != current.LUID || !strings.EqualFold(d.GUID.String(), current.GUID) {
			return errors.New("USB_MAC_RESTORE_HELD_MAPPING_UNPROVEN")
		}
		got, has, e := readSecondaryBinding(dir)
		if e != nil || !has || got != mapped {
			return errors.New("USB_MAC_RESTORE_MAPPING_CHANGED")
		}
		return netconfig.VerifyOwnedMacRecreatedNative(current.Index, current.LUID, old.Instance)
	}
	store, has, e := readConfigReceiptFile(dir)
	if e != nil || !has || !store.RestoreRequested {
		return errors.New("USB_MAC_RESTORE_ORIGINAL_UNPROVEN")
	}
	for _, dad := range store.DAD {
		if dad.Scope.Role != "mac" {
			continue
		}
		original := dad.Scope
		if original.LUID != source.LUID {
			return errors.New("USB_MAC_RESTORE_DAD_SOURCE_CHANGED")
		}
		if e = restoreDADZeroForOwnedMappingUnlocked(ctx, dir, original, current, mapped.OriginalSHA256, true, func(actualOriginal Scope) error {
			if actualOriginal != original {
				return errors.New("USB_MAC_RESTORE_DAD_ORIGINAL_CHANGED")
			}
			if _, e := exactSecondaryOriginalForMode(dir, mapped, true); e != nil {
				return e
			}
			return verify()
		}); e != nil {
			return e
		}
	}
	if e = restorePersistentUnlocked(ctx, dir, current, verify, WintunProfileOps(current, verify, nil), func(original persistentOriginal) bool {
		return original.Scope == mapped.OriginalScope && persistentDigest(original) == mapped.OriginalSHA256 && original.Profile != nil && original.AppliedAddress != nil
	}); e != nil {
		return e
	}
	if e = verify(); e != nil {
		return e
	}
	if e = macOriginalsRestoredUnlocked(dir); e != nil {
		return e
	}
	restored := mapped
	restored.State = "restored"
	if e = writeSecondaryBinding(dir, restored, &mapped); e != nil {
		return e
	}
	d.Close()
	return finishMacRestoreBindingUnlocked(ctx, dir, restored, verifyInstalledOwner)
}

func macOriginalsRestoredUnlocked(dir string) error {
	store, found, e := readConfigReceiptFile(dir)
	if e != nil || !found || !store.RestoreRequested {
		return errors.New("USB_MAC_RESTORE_INTENT_UNPROVEN")
	}
	for _, o := range store.Persistent {
		if o.Scope.Role == "mac" || strings.EqualFold(o.Scope.GUID, MacGUID) {
			return errors.New("USB_MAC_RESTORE_ORIGINAL_REMAINS")
		}
	}
	for _, o := range store.DAD {
		if o.Scope.Role == "mac" || strings.EqualFold(o.Scope.GUID, MacGUID) {
			return errors.New("USB_MAC_RESTORE_ORIGINAL_REMAINS")
		}
	}
	return nil
}

func finishMacRestoreBindingUnlocked(ctx context.Context, dir string, expected secondaryBinding, verifyInstalledOwner func() error) error {
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if verifyInstalledOwner() != nil {
			return errors.New("USB_MAC_RESTORE_INSTALLED_OWNER_UNPROVEN")
		}
		v, found, e := readSecondaryBinding(dir)
		if e != nil || !found || v != expected || v.State != "restored" {
			return errors.New("USB_MAC_RESTORE_COMPLETION_CHANGED")
		}
		if e = macOriginalsRestoredUnlocked(dir); e != nil {
			return e
		}
		if e = netconfig.VerifyOwnedMacFactorySourceNative(v.CurrentScope.Index, v.CurrentScope.LUID, v.Instance); e != nil {
			return e
		}
		absent, e := netconfig.MacAdapterAbsentNative()
		if e != nil || !absent {
			return errors.New("USB_MAC_RESTORE_FACTORY_ABSENCE_UNPROVEN")
		}
	}
	if os.Remove(filepath.Join(dir, secondaryBindingFile)) != nil {
		return errors.New("USB_MAC_RESTORE_BINDING_REMOVE_FAILED")
	}
	_, found, e := readSecondaryBinding(dir)
	if e != nil || found {
		return errors.New("USB_MAC_RESTORE_BINDING_REMAINS")
	}
	return nil
}
