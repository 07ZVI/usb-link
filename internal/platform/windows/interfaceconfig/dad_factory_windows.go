//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
	"strings"
	"time"
)

// RestoreDADZeroForOwnedFactory restores the recorded setting to one actual
// returned factory mapping, not to an absent old LUID. The mandatory callback
// must fresh-prove the protected mapped transaction, immutable original/journal
// SHA, held official returned handle and same typed native instance. It may not
// re-enter this package. No diagnostic snapshot or same-GUID observation grants
// this permission. Unproven/external values retain the original obligation.
func RestoreDADZeroForOwnedFactory(ctx context.Context, dir string, original, current Scope, persistentSHA string, verifyFactory func(Scope) error) (result error) {
	return restoreDADZeroForOwnedMapping(ctx, dir, original, current, persistentSHA, false, verifyFactory)
}

// RestoreDADZeroForOwnedProjection can change only an index on the identical
// saved LUID. Its callback proves the protected completed source journal and
// exact native instance; it never authorizes a new-LUID factory result.
func RestoreDADZeroForOwnedProjection(ctx context.Context, dir string, original, current Scope, persistentSHA string, verifyReady func(Scope) error) error {
	if e := validateDADProjection(original, current); e != nil {
		return e
	}
	return restoreDADZeroForOwnedMapping(ctx, dir, original, current, persistentSHA, false, verifyReady)
}

// RestoreDADZeroForOwnedProjectionForRestore is only an uninstall restoring
// phase. It must precede consuming the persistent original/Store obligation.
func RestoreDADZeroForOwnedProjectionForRestore(ctx context.Context, dir string, original, current Scope, persistentSHA string, verifyRestoring func(Scope) error) error {
	if e := validateDADProjection(original, current); e != nil {
		return e
	}
	return restoreDADZeroForOwnedMapping(ctx, dir, original, current, persistentSHA, true, verifyRestoring)
}
func restoreDADZeroForOwnedMapping(ctx context.Context, dir string, original, current Scope, persistentSHA string, restore bool, verifyFactory func(Scope) error) (result error) {
	start := time.Now()
	defer func() { recordTiming(current.Role, "dad_restore", start, result, false) }()
	if !shaPattern.MatchString(persistentSHA) || verifyFactory == nil {
		return errors.New("USB_DAD_FACTORY_PROOF_INVALID")
	}
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	return restoreDADZeroForOwnedMappingUnlocked(ctx, dir, original, current, persistentSHA, restore, verifyFactory)
}

// Caller holds configMutex through its protected factory transaction.
func restoreDADZeroForOwnedMappingUnlocked(ctx context.Context, dir string, original, current Scope, persistentSHA string, restore bool, verifyFactory func(Scope) error) (result error) {
	verify := func() error { return verifyFactory(original) }
	var e error
	if e = fresh(ctx, current, verify); e != nil {
		return e
	}
	store, found, e := readConfigReceiptFile(dir)
	if e != nil {
		return e
	}
	if !found {
		return errors.New("USB_DAD_FACTORY_PERSISTENT_ORIGINAL_MISSING")
	}
	var baseline *persistentOriginal
	for i := range store.Persistent {
		if store.Persistent[i].Scope.Role == original.Role && strings.EqualFold(store.Persistent[i].Scope.GUID, original.GUID) {
			baseline = &store.Persistent[i]
		}
	}
	if baseline == nil {
		return errors.New("USB_DAD_FACTORY_PERSISTENT_ORIGINAL_MISSING")
	}
	for i, dad := range store.DAD {
		if strings.EqualFold(dad.Scope.GUID, original.GUID) {
			before, e := getRow(current)
			if e != nil {
				return e
			}
			if e = validateDADFactoryOriginal(original, current, persistentSHA, *baseline, dad, before.DadTransmits); e != nil {
				return e
			}
			if store.RestoreRequested != restore {
				return errors.New("USB_DAD_FACTORY_UNINSTALL_PENDING")
			}
			if e = verifyPersistentStore(ctx, current, verify, *baseline); e != nil {
				return e
			}
			last, has, e := readConfigReceiptFile(dir)
			if e != nil || !has || !sameConfigReceipt(store, last) {
				return errors.New("USB_DAD_FACTORY_ORIGINAL_CHANGED")
			}
			if e = fresh(ctx, current, verify); e != nil {
				return e
			}
			second, e := getRow(current)
			if e != nil || second != before {
				return errors.New("USB_DAD_FACTORY_ROW_CHANGED")
			}
			if before.DadTransmits != dad.Original {
				if e = setDad(ctx, current, before, dad.Original, verify); e != nil {
					return e
				}
			}
			after, e := getRow(current)
			if e != nil {
				return e
			}
			expected := before
			expected.DadTransmits = dad.Original
			// IPv4 SetIpInterfaceEntry requires SitePrefixLength=0; accept only that
			// documented normalization or the identical observed value, no third value.
			if after.SitePrefixLength != 0 && after.SitePrefixLength != before.SitePrefixLength {
				return errors.New("USB_DAD_FACTORY_ROW_CHANGED")
			}
			expected.SitePrefixLength = after.SitePrefixLength
			if after != expected {
				return errors.New("USB_DAD_FACTORY_ROW_CHANGED")
			}
			if e = fresh(ctx, current, verify); e != nil {
				return e
			}
			if e = verifyPersistentStore(ctx, current, verify, *baseline); e != nil {
				return e
			}
			last, has, e = readConfigReceiptFile(dir)
			if e != nil || !has || !sameConfigReceipt(store, last) {
				return errors.New("USB_DAD_FACTORY_ORIGINAL_CHANGED")
			}
			store.DAD = append(store.DAD[:i], store.DAD[i+1:]...)
			return writeConfigReceiptFile(dir, store, true)
		}
	}
	return nil
}
