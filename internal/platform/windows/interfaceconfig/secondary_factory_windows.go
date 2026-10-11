//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
)

var secondaryTicks = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

// CaptureSecondaryFactoryBinding follows successful persistent creation and
// two complete active/Store observations under the caller's configuration lease.
// It creates no replacement original and cannot import an old unknown mapping.
func CaptureSecondaryFactoryBinding(ctx context.Context, r *RetainedSecondary) error {
	if r == nil || r.scope.Role != "mac" || r.device == nil || !r.device.FactoryHandleHeld() || !persistentEnabled.Load() {
		return errors.New("USB_SECONDARY_FACTORY_SCOPE_REQUIRED")
	}
	if e := r.VerifyAddress(ctx, interfaceProof(r.scope)); e != nil {
		return e
	}
	instance, e := netconfig.CaptureOwnedMacNative(r.scope.Index, r.scope.LUID, false)
	if e != nil {
		return e
	}
	if e = netconfig.VerifyOwnedMacRecreatedNative(r.scope.Index, r.scope.LUID, instance); e != nil {
		return e
	}
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	last, e := verifyPersistentModeUnlocked(ctx, r.dir, r.scope, r.verify, r.profile, r.baseline.AddressMode, r.baseline.Created)
	if e != nil || last != r.baseline {
		return errors.New("USB_SECONDARY_FACTORY_CAPTURE_CHANGED")
	}
	if e = netconfig.VerifyOwnedMacRecreatedNative(r.scope.Index, r.scope.LUID, instance); e != nil {
		return e
	}
	old, found, e := readSecondaryBinding(r.dir)
	if e != nil {
		return e
	}
	next := secondaryBinding{Version: 1, OriginalSHA256: r.baseline.ReceiptSHA256, OriginalScope: r.scope, CurrentScope: r.scope, Instance: instance, State: "ready", Created: r.baseline.Created, Mode: r.baseline.AddressMode}
	if _, e = exactSecondaryOriginal(r.dir, next); e != nil {
		return e
	}
	if found {
		if old != next {
			return errors.New("USB_SECONDARY_FACTORY_BINDING_EXISTS")
		}
		return nil
	}
	return writeSecondaryBinding(r.dir, next, nil)
}
func interfaceProof(s Scope) usbaddress.InterfaceProof {
	return usbaddress.InterfaceProof{Index: s.Index, LUID: s.LUID, GUID: s.GUID}
}

// MarkSecondaryFactoryClosed runs after packet workers/session permissions are
// joined/removed, before the creator handle Close. Closed is only an obligation:
// the next factory attempt must independently prove exact native nonpresence.
func (r *RetainedSecondary) markFactoryClosed() error {
	if r.device == nil || !r.device.FactoryHandleHeld() {
		return errors.New("USB_SECONDARY_FACTORY_HANDLE_REQUIRED")
	}
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	old, found, e := readSecondaryBinding(r.dir)
	if e != nil || !found {
		return errors.New("USB_SECONDARY_FACTORY_BINDING_UNPROVEN")
	}
	if old.State != "ready" || old.CurrentScope != r.scope || old.Created != r.baseline.Created || old.Mode != r.baseline.AddressMode || old.OriginalSHA256 != r.baseline.ReceiptSHA256 {
		return errors.New("USB_SECONDARY_FACTORY_CLOSE_UNPROVEN")
	}
	if _, e = exactSecondaryOriginal(r.dir, old); e != nil {
		return e
	}
	if e = netconfig.VerifyOwnedMacRecreatedNative(r.scope.Index, r.scope.LUID, old.Instance); e != nil {
		return e
	}
	next := old
	next.State = "closed"
	return writeSecondaryBinding(r.dir, next, &old)
}

func (r *RetainedSecondary) localCleanupOwner() error {
	if r == nil || r.scope.Role != "mac" {
		return errors.New("USB_SECONDARY_FACTORY_SCOPE_REQUIRED")
	}
	v, found, e := readSecondaryBinding(r.dir)
	if e != nil || !found || v.State != "ready" || v.CurrentScope != r.scope || v.Created != r.baseline.Created || v.Mode != r.baseline.AddressMode || v.OriginalSHA256 != r.baseline.ReceiptSHA256 {
		return errors.New("USB_SECONDARY_FACTORY_CLEANUP_BINDING_UNPROVEN")
	}
	return netconfig.VerifyOwnedMacRecreatedNative(r.scope.Index, r.scope.LUID, v.Instance)
}

// RecreatePersistentMac is entered only with a protected exact factory original
// and previously completed closed binding. Unknown attempts remain fenced; no
// failed proof falls back to name-based Open/Create. The official synchronous
// call is joined before returning and owns the configuration lease throughout.
func RecreatePersistentMac(ctx context.Context, dir, dll string, owner func(Scope) error, profiles func(Scope) ProfileOps) (*wintun.Device, *RetainedSecondary, bool, error) {
	if !persistentEnabled.Load() {
		return nil, nil, false, nil
	}
	if ctx == nil || owner == nil || profiles == nil {
		return nil, nil, true, errors.New("USB_SECONDARY_FACTORY_OWNER_REQUIRED")
	}
	finish, e := lockConfig()
	if e != nil {
		return nil, nil, true, e
	}
	old, found, e := readSecondaryBinding(dir)
	if e != nil || !found {
		finish()
		return nil, nil, found, e
	}
	if _, e = exactSecondaryOriginal(dir, old); e != nil {
		finish()
		return nil, nil, true, e
	}
	if old.State != "closed" && old.State != "ready" {
		finish()
		return nil, nil, true, errors.New("USB_SECONDARY_FACTORY_UNKNOWN_PHASE")
	}
	s := old.CurrentScope
	// This callback must verify fresh USB identity/consent; nonpresent Wintun
	// proof is independent and does not require an active-address Ready flag.
	pre := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := owner(s); e != nil {
			return errors.New("USB_SECONDARY_FACTORY_USB_OWNER_UNPROVEN")
		}
		got, found, e := readSecondaryBinding(dir)
		if e != nil || !found || got != old {
			return errors.New("USB_SECONDARY_FACTORY_BINDING_CHANGED")
		}
		e = netconfig.VerifyOwnedMacFactorySourceNative(s.Index, s.LUID, old.Instance)
		if e != nil {
			return errors.New("USB_SECONDARY_FACTORY_NONPRESENT_UNPROVEN")
		}
		return nil
	}
	if e = pre(); e != nil {
		finish()
		return nil, nil, true, e
	}
	if old.State == "ready" {
		closed := old
		closed.State = "closed"
		if e = writeSecondaryBinding(dir, closed, &old); e != nil {
			finish()
			return nil, nil, true, e
		}
		old = closed
	}

	pin, e := netconfig.PinVerifiedWintunNative(dll, log.New(os.Stderr, "USB secondary factory: ", 0))
	if e != nil {
		finish()
		return nil, nil, true, e
	}
	defer pin.Close()
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		finish()
		return nil, nil, true, e
	}
	ticks, _, _ := secondaryTicks.Call()
	if ticks == 0 {
		finish()
		return nil, nil, true, errors.New("USB_SECONDARY_FACTORY_TICKS_UNPROVEN")
	}
	attempt := old
	attempt.State = "attempt"
	attempt.Attempt = hex.EncodeToString(nonce[:])
	attempt.Ticks = uint64(ticks)
	attempt.Created = 0
	attempt.Mode = ""
	if e = writeSecondaryBinding(dir, attempt, &old); e != nil {
		finish()
		return nil, nil, true, e
	}
	before := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := owner(s); e != nil {
			return errors.New("USB_SECONDARY_FACTORY_USB_OWNER_UNPROVEN")
		}
		got, found, e := readSecondaryBinding(dir)
		if e != nil || !found || got != attempt {
			return errors.New("USB_SECONDARY_FACTORY_BINDING_CHANGED")
		}
		if _, e = exactSecondaryOriginal(dir, attempt); e != nil {
			return e
		}
		e = netconfig.VerifyOwnedMacFactorySourceNative(s.Index, s.LUID, old.Instance)
		if e != nil {
			return errors.New("USB_SECONDARY_FACTORY_NONPRESENT_CHANGED")
		}
		return nil
	}
	observation := wintun.OwnedCreateObservation{}
	d, e := wintun.CreateOwnedNonpresentMac(dll, before, &observation)
	if e != nil {
		finish()
		return nil, nil, true, e
	} // attempt remains on all unknown calls.
	nextScope := Scope{"mac", MacGUID, d.Index, d.LUID}
	if !observation.Called || !observation.Returned || !observation.Succeeded || !observation.FixedGUIDVerified || validateScope(nextScope) != nil || netconfig.VerifyOwnedMacRecreatedNative(d.Index, d.LUID, old.Instance) != nil {
		d.Close()
		finish()
		return nil, nil, true, errors.New("USB_SECONDARY_FACTORY_RETURN_UNPROVEN")
	}
	mapped := attempt
	mapped.State = "mapped"
	mapped.CurrentScope = nextScope
	if e = writeSecondaryBinding(dir, mapped, &attempt); e != nil {
		d.Close()
		finish()
		return nil, nil, true, e
	}
	verify := func() error {
		if e := owner(nextScope); e != nil {
			return e
		}
		return netconfig.VerifyOwnedMacRecreatedNative(d.Index, d.LUID, old.Instance)
	}
	// A prior interrupted DAD mutation belongs to the exact saved source LUID,
	// not automatically to the first immutable Store scope or any same-GUID row.
	prior, exists, e := readConfigReceiptFile(dir)
	if e != nil || !exists {
		d.Close()
		finish()
		return nil, nil, true, errors.New("USB_SECONDARY_FACTORY_DAD_ORIGINAL_UNPROVEN")
	}
	for _, dad := range prior.DAD {
		if dad.Scope.Role == "mac" {
			originalScope := dad.Scope
			verifyMapped := func(observed Scope) error {
				if observed != originalScope || observed.LUID != s.LUID || observed.Role != s.Role || !strings.EqualFold(observed.GUID, s.GUID) || !d.FactoryHandleHeld() || d.Index != nextScope.Index || d.LUID != nextScope.LUID {
					return errors.New("USB_SECONDARY_FACTORY_DAD_SOURCE_CHANGED")
				}
				got, has, e := readSecondaryBinding(dir)
				if e != nil || !has || got != mapped {
					return errors.New("USB_SECONDARY_FACTORY_DAD_MAPPING_CHANGED")
				}
				if _, e = exactSecondaryOriginal(dir, mapped); e != nil {
					return e
				}
				return verify()
			}
			if e = restoreDADZeroForOwnedMappingUnlocked(ctx, dir, originalScope, nextScope, old.OriginalSHA256, false, verifyMapped); e != nil {
				d.Close()
				finish()
				return nil, nil, true, e
			}
		}
	}
	profile := profiles(nextScope)
	a, e := verifyPersistentModeUnlocked(ctx, dir, nextScope, verify, profile, "persistent", 0)
	if e != nil {
		d.Close()
		finish()
		return nil, nil, true, e
	}
	b, e := verifyPersistentModeUnlocked(ctx, dir, nextScope, verify, profile, "persistent", 0)
	if e != nil || a != b || a.ReceiptSHA256 != old.OriginalSHA256 {
		d.Close()
		finish()
		return nil, nil, true, errors.New("USB_SECONDARY_FACTORY_STORE_ACTIVE_CHANGED")
	}
	if _, e = exactSecondaryOriginal(dir, mapped); e != nil {
		d.Close()
		finish()
		return nil, nil, true, e
	}
	if e = verify(); e != nil {
		d.Close()
		finish()
		return nil, nil, true, e
	}
	ready := mapped
	ready.State = "ready"
	ready.Created = b.Created
	ready.Mode = "persistent"
	ready.Attempt = ""
	ready.Ticks = 0
	e = writeSecondaryBinding(dir, ready, &mapped)
	finish()
	if e != nil {
		d.Close()
		return nil, nil, true, e
	}
	lease := &RetainedSecondary{dir: dir, scope: nextScope, baseline: b, verify: verify, profile: profile, device: d}
	return d, lease, true, nil
}

func (r *RetainedSecondary) clearRestoredFactoryBinding() error {
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	v, found, e := readSecondaryBinding(r.dir)
	if e != nil {
		return e
	}
	if !found {
		return nil
	}
	if v.State != "ready" || v.CurrentScope != r.scope || v.Created != r.baseline.Created || v.OriginalSHA256 != r.baseline.ReceiptSHA256 {
		return errors.New("USB_SECONDARY_RESTORE_BINDING_UNPROVEN")
	}
	store, found, e := readConfigReceiptFile(r.dir)
	if e != nil || !found || !store.RestoreRequested {
		return errors.New("USB_SECONDARY_RESTORE_INTENT_UNPROVEN")
	}
	for _, o := range store.Persistent {
		if strings.EqualFold(o.Scope.GUID, r.scope.GUID) {
			return errors.New("USB_SECONDARY_RESTORE_ORIGINAL_REMAINS")
		}
	}
	for _, o := range store.DAD {
		if strings.EqualFold(o.Scope.GUID, r.scope.GUID) {
			return errors.New("USB_SECONDARY_RESTORE_ORIGINAL_REMAINS")
		}
	}
	if e = netconfig.VerifyOwnedMacRecreatedNative(r.scope.Index, r.scope.LUID, v.Instance); e != nil {
		return e
	}
	if os.Remove(filepath.Join(r.dir, secondaryBindingFile)) != nil {
		return errors.New("USB_SECONDARY_RESTORE_BINDING_REMOVE_FAILED")
	}
	_, present, e := readSecondaryBinding(r.dir)
	if e != nil || present {
		return errors.New("USB_SECONDARY_RESTORE_BINDING_REMAINS")
	}
	return nil
}

// RestorePersistentMacFactory is uninstall-only and needs no live USB peer.
// A mapped record proves a returned factory handle; an attempt is unknown and
// cannot authorize restoration/adoption. Original values remain independently
// verified by the typed restore path before their checkpoint is consumed.
func RestorePersistentMacFactory(ctx context.Context, dir string) error {
	requested, e := PersistentRestoreRequested(dir)
	if e != nil || !requested {
		return errors.New("USB_SECONDARY_RESTORE_INTENT_REQUIRED")
	}
	v, found, e := readSecondaryBinding(dir)
	if e != nil {
		return e
	}
	if !found {
		return nil
	}
	if v.State != "ready" && v.State != "mapped" {
		return errors.New("USB_SECONDARY_RESTORE_FACTORY_PHASE_UNPROVEN")
	}
	verify := func() error {
		got, present, e := readSecondaryBinding(dir)
		if e != nil || !present || got != v {
			return errors.New("USB_SECONDARY_RESTORE_BINDING_CHANGED")
		}
		return netconfig.VerifyOwnedMacRecreatedNative(v.CurrentScope.Index, v.CurrentScope.LUID, v.Instance)
	}
	if e = verify(); e != nil {
		return e
	}
	profiles := WintunProfileOps(v.CurrentScope, verify, nil)
	if e = RestorePersistent(ctx, dir, v.CurrentScope, verify, profiles); e != nil {
		return e
	}
	if e = RestoreDADZero(ctx, dir, v.CurrentScope, verify); e != nil {
		return e
	}
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	got, present, e := readSecondaryBinding(dir)
	if e != nil || !present || got != v {
		return errors.New("USB_SECONDARY_RESTORE_BINDING_CHANGED")
	}
	store, found, e := readConfigReceiptFile(dir)
	if e != nil || !found || !store.RestoreRequested {
		return errors.New("USB_SECONDARY_RESTORE_INTENT_UNPROVEN")
	}
	for _, o := range store.Persistent {
		if strings.EqualFold(o.Scope.GUID, v.CurrentScope.GUID) {
			return errors.New("USB_SECONDARY_RESTORE_ORIGINAL_REMAINS")
		}
	}
	for _, o := range store.DAD {
		if strings.EqualFold(o.Scope.GUID, v.CurrentScope.GUID) {
			return errors.New("USB_SECONDARY_RESTORE_ORIGINAL_REMAINS")
		}
	}
	if e = verify(); e != nil {
		return e
	}
	if os.Remove(filepath.Join(dir, secondaryBindingFile)) != nil {
		return errors.New("USB_SECONDARY_RESTORE_BINDING_REMOVE_FAILED")
	}
	_, present, e = readSecondaryBinding(dir)
	if e != nil || present {
		return errors.New("USB_SECONDARY_RESTORE_BINDING_REMAINS")
	}
	return nil
}
