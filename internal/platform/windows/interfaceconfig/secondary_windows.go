//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
	"sync"
)

// RetainedSecondary is constructed only by a protected exactScope and two fresh
// complete native observations. Its private baseline is not a remote option.
// Callers retain ConfigurationLock and a fresh USB/consent owner throughout;
// call Close only after all packet workers are joined, before releasing owner.
type RetainedSecondary struct {
	dir        string
	scope      Scope
	baseline   ActiveOwnership
	verify     func() error
	profile    ProfileOps
	device     *wintun.Device
	once       sync.Once
	closeError error
}

func (r *RetainedSecondary) Scope() Scope {
	if r == nil {
		return Scope{}
	}
	return r.scope
}
func (r *RetainedSecondary) Created() int64 {
	if r == nil {
		return 0
	}
	return r.baseline.Created
}
func (r *RetainedSecondary) AddressMode() string {
	if r == nil {
		return ""
	}
	return r.baseline.AddressMode
}
func (r *RetainedSecondary) ReceiptSHA256() string {
	if r == nil {
		return ""
	}
	return r.baseline.ReceiptSHA256
}
func (r *RetainedSecondary) VerifyAddress(ctx context.Context, p usbaddress.InterfaceProof) error {
	if r == nil || p.Role != "" || p.Index != r.scope.Index || p.LUID != r.scope.LUID || !strings.EqualFold(p.GUID, r.scope.GUID) {
		return errors.New("USB_PERSISTENT_SECONDARY_SCOPE_CHANGED")
	}
	current, e := verifyPersistentMode(ctx, r.dir, r.scope, r.verify, r.profile, r.baseline.AddressMode, r.baseline.Created)
	if e != nil {
		return e
	}
	if current != r.baseline {
		return errors.New("USB_PERSISTENT_SECONDARY_BASELINE_CHANGED")
	}
	return nil
}
func (r *RetainedSecondary) Close() error {
	if r == nil {
		return errors.New("USB_PERSISTENT_SECONDARY_LEASE_MISSING")
	}
	r.once.Do(func() {
		if r.device != nil {
			defer r.device.Close()
		}
		requested, e := PersistentRestoreRequested(r.dir)
		if e != nil {
			r.closeError = e
			return
		}
		cleanupVerify := r.verify
		cleanupProfile := r.profile
		if r.scope.Role == "mac" {
			cleanupVerify = r.localCleanupOwner
			cleanupProfile = WintunProfileOps(r.scope, cleanupVerify, nil)
		}
		r.closeError = runSecondaryClose(requested, func() error {
			// Runtime negotiated MTU changes no persistent original. Normal
			// stop still requires this exact session Created and receipt.
			current, e := verifyRetainedRuntime(context.Background(), r.dir, r.scope, cleanupVerify, cleanupProfile, r.baseline.Created, r.baseline.AddressMode)
			if e != nil || current.Scope != r.baseline.Scope || current.Created != r.baseline.Created || current.ReceiptSHA256 != r.baseline.ReceiptSHA256 {
				return errors.New("USB_PERSISTENT_SECONDARY_CLOSE_UNPROVEN")
			}
			return nil
		}, func() error {
			// Recovery permits only fresh typed original/desired values and
			// keeps the obligation when any step remains unknown.
			return RestorePersistent(context.Background(), r.dir, r.scope, cleanupVerify, cleanupProfile)
		}, func() error { return RestoreDADZero(context.Background(), r.dir, r.scope, cleanupVerify) })

		if r.closeError == nil && requested && r.scope.Role == "mac" {
			r.closeError = r.clearRestoredFactoryBinding()
		}
		if r.closeError == nil && !requested && r.scope.Role == "mac" && r.device != nil && r.device.FactoryHandleHeld() {
			r.closeError = r.markFactoryClosed()
		}
	})
	return r.closeError
}

// CapturePersistentSecondary follows the caller's successful owned factory
// address creation (Mac253/iPad254), before any negotiated jumbo MTU. It is the
// shared lifecycle hook for both a new adapter and an already-created iPad node.
func CapturePersistentSecondary(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) (*RetainedSecondary, error) {
	if s.Role != "mac" && s.Role != "ipad" {
		return nil, errors.New("USB_PERSISTENT_SECONDARY_SCOPE_REQUIRED")
	}
	if !persistentEnabled.Load() {
		return nil, nil
	}
	if _, e := ApplyPersistent(ctx, dir, s, verifyOwner, profile); e != nil {
		return nil, e
	}
	return verifyRetainedSecondary(ctx, dir, s, verifyOwner, profile)
}

// CapturePersistentSecondaryAfterAddress follows the owner's durable exact
// current-session Created checkpoint. PersistentStore may leave that active
// row at its original finite lifetime until next boot; it is never adopted as
// an infinite row or used to rebind its creation stamp.
func CapturePersistentSecondaryAfterAddress(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps, created int64) (*RetainedSecondary, error) {
	if created <= 0 || (s.Role != "mac" && s.Role != "ipad") {
		return nil, errors.New("USB_PERSISTENT_SECONDARY_CREATED_REQUIRED")
	}
	if !persistentEnabled.Load() {
		return nil, nil
	}
	if _, e := ApplyPersistent(ctx, dir, s, verifyOwner, profile); e != nil {
		return nil, e
	}
	first, e := verifyPersistentMode(ctx, dir, s, verifyOwner, profile, "legacy", created)
	if e != nil {
		first, e = verifyPersistentMode(ctx, dir, s, verifyOwner, profile, "persistent", created)
	}
	if e != nil || first.Created != created {
		return nil, errors.New("USB_PERSISTENT_SECONDARY_CREATED_CHANGED")
	}
	last, e := verifyPersistentMode(ctx, dir, s, verifyOwner, profile, first.AddressMode, created)
	if e != nil {
		return nil, e
	}
	if first != last {
		return nil, errors.New("USB_PERSISTENT_SECONDARY_PROOF_CHANGED")
	}

	return &RetainedSecondary{dir: dir, scope: s, baseline: last, verify: verifyOwner, profile: profile}, nil
}

// RetainExistingSecondary does not apply CIM, capture new originals, or migrate
// an old GUID/LUID. It is suitable for the same actual native iPad instance; a
// changed volatile mapping remains failclosed pending a separate migration.
func RetainExistingSecondary(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) (*RetainedSecondary, bool, error) {
	if s.Role != "mac" && s.Role != "ipad" {
		return nil, false, errors.New("USB_PERSISTENT_SECONDARY_SCOPE_REQUIRED")
	}
	if !persistentEnabled.Load() {
		return nil, false, nil
	}
	found, e := HasPersistentObligation(dir, s)
	if e != nil || !found {
		return nil, found, e
	}
	r, e := verifyRetainedSecondary(ctx, dir, s, verifyOwner, profile)
	return r, true, e
}

// RetainSecondarySession requires the caller's protected completed session
// binding in addition to the original-value receipt. A boot-created infinite
// address may have a new Created only under the same exact volatile mapping,
// unchanged target receipt and two fresh complete observations. No new scope
// or address is created and no failing observation falls through to mutation.
func RetainSecondarySession(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps, oldCreated int64, oldMode, oldReceipt string) (*RetainedSecondary, error) {
	if !persistentEnabled.Load() || oldCreated <= 0 || (oldMode != "legacy" && oldMode != "persistent") || !shaPattern.MatchString(oldReceipt) || (s.Role != "mac" && s.Role != "ipad") {
		return nil, errors.New("USB_PERSISTENT_SECONDARY_JOURNAL_UNPROVEN")
	}
	observe := func() (ActiveOwnership, error) {
		a, e := verifyRetainedRuntime(ctx, dir, s, verifyOwner, profile, oldCreated, oldMode)
		if e == nil {
			a.AddressMode = oldMode
			return a, nil
		}
		return VerifyPersistentActive(ctx, dir, s, verifyOwner, profile)
	}
	a, e := observe()
	if e != nil {
		return nil, e
	}
	b, e := observe()
	if e != nil {
		return nil, e
	}
	if a != b || a.Scope != s || a.ReceiptSHA256 != oldReceipt {
		return nil, errors.New("USB_PERSISTENT_SECONDARY_JOURNAL_CHANGED")
	}
	return &RetainedSecondary{dir: dir, scope: s, baseline: b, verify: verifyOwner, profile: profile}, nil
}

func verifyRetainedSecondary(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) (*RetainedSecondary, error) {
	first, e := VerifyPersistentActive(ctx, dir, s, verifyOwner, profile)
	if e != nil {
		return nil, e
	}
	last, e := VerifyPersistentActive(ctx, dir, s, verifyOwner, profile)
	if e != nil {
		return nil, e
	}
	if first != last {
		return nil, errors.New("USB_PERSISTENT_SECONDARY_PROOF_CHANGED")
	}
	return &RetainedSecondary{dir: dir, scope: s, baseline: last, verify: verifyOwner, profile: profile}, nil
}
func retainedMacScope(dir string) (Scope, bool, error) {
	finish, e := lockConfig()
	if e != nil {
		return Scope{}, false, e
	}
	defer finish()
	record, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return Scope{}, false, e
	}
	for _, r := range record.Persistent {
		if r.Scope.Role == "mac" {
			if record.RestoreRequested {
				return Scope{}, true, errors.New("USB_PERSISTENT_UNINSTALL_PENDING")
			}
			return r.Scope, true, nil
		}
	}
	return Scope{}, false, nil
}

// OpenPersistentMac is no-Create. No-originals returns found=false so the caller
// may use its normal factory. Any present original, even partial or stale,
// returns found=true and must never fall through to another Create.
func OpenPersistentMac(ctx context.Context, dir, dll string, verifyOwner func(Scope) error, profiles func(Scope) ProfileOps) (*wintun.Device, *RetainedSecondary, bool, error) {
	if !persistentEnabled.Load() {
		return nil, nil, false, nil
	}
	if ctx == nil || verifyOwner == nil || profiles == nil {
		return nil, nil, false, errors.New("USB_PERSISTENT_MAC_OWNER_REQUIRED")
	}
	s, found, e := retainedMacScope(dir)
	if e != nil || !found {
		return nil, nil, found, e
	}
	binding, hasBinding, e := readSecondaryBinding(dir)
	if e != nil || !hasBinding {
		return nil, nil, true, errors.New("USB_SECONDARY_FACTORY_BINDING_UNPROVEN")
	}
	if binding.State != "ready" {
		return RecreatePersistentMac(ctx, dir, dll, verifyOwner, profiles)
	}
	s = binding.CurrentScope
	projected := windows.MibIfRow2{InterfaceLuid: s.LUID}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &projected) == nil {
		if projected.InterfaceLuid != s.LUID || !strings.EqualFold(projected.InterfaceGuid.String(), s.GUID) || windows.UTF16ToString(projected.Alias[:]) != "USB Link" || projected.Type != 53 || projected.InterfaceIndex == 0 {
			return nil, nil, true, errors.New("USB_PERSISTENT_MAC_INDEX_PROJECTION_UNPROVEN")
		}
		s.Index = projected.InterfaceIndex
	}
	verify := func() error {
		if e := verifyOwner(s); e != nil {
			return e
		}
		return netconfig.VerifyOwnedMacRecreatedNative(s.Index, s.LUID, binding.Instance)
	}
	r, e := RetainSecondarySession(ctx, dir, s, verify, profiles(s), binding.Created, binding.Mode, binding.OriginalSHA256)
	if e != nil {
		// Only exact source nonpresence/absence can move a completed ready record
		// to a factory attempt. An arbitrary failed active proof is never enough.
		if netconfig.VerifyOwnedMacFactorySourceNative(s.Index, s.LUID, binding.Instance) != nil {
			return nil, nil, true, e
		}
		return RecreatePersistentMac(ctx, dir, dll, verifyOwner, profiles)
	}
	beforeOpen := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return r.VerifyAddress(ctx, usbaddress.InterfaceProof{Index: s.Index, GUID: s.GUID, LUID: s.LUID})
	}
	pin, e := netconfig.PinVerifiedWintunNative(dll, log.New(os.Stderr, "USB retained Mac: ", 0))
	if e != nil {
		return nil, nil, true, e
	}
	defer pin.Close()
	d, e := wintun.OpenOwnedPersistentMac(dll, s.Index, s.LUID, beforeOpen)
	if e != nil {
		return nil, nil, true, e
	}
	r.device = d
	finish, e := lockConfig()
	if e != nil {
		d.Close()
		return nil, nil, true, e
	}
	current, found, e := readSecondaryBinding(dir)
	if e == nil && (!found || current != binding) {
		e = errors.New("USB_PERSISTENT_MAC_OPEN_BINDING_CHANGED")
	}
	if e == nil {
		a, pe := verifyPersistentModeUnlocked(ctx, dir, s, verify, profiles(s), r.baseline.AddressMode, r.baseline.Created)
		if pe != nil || a != r.baseline {
			e = errors.New("USB_PERSISTENT_MAC_OPEN_ACTIVE_CHANGED")
		}
	}
	if e == nil {
		a, pe := verifyPersistentModeUnlocked(ctx, dir, s, verify, profiles(s), r.baseline.AddressMode, r.baseline.Created)
		if pe != nil || a != r.baseline {
			e = errors.New("USB_PERSISTENT_MAC_OPEN_ACTIVE_CHANGED")
		}
	}
	if e == nil {
		if _, oe := exactSecondaryOriginal(dir, binding); oe != nil {
			e = oe
		}
	}
	if e == nil {
		e = verify()
	}
	if e == nil {
		next := binding
		next.CurrentScope = s
		next.Created = r.baseline.Created
		next.Mode = r.baseline.AddressMode
		if next != binding {
			e = writeSecondaryBinding(dir, next, &binding)
		}
		if e == nil {
			// A reboot can reproject only the index of this same saved LUID.
			// Restore its old DAD obligation before a new optional capture; an
			// Open handle cannot authorize a new-LUID factory mapping.
			store, has, re := readConfigReceiptFile(dir)
			if re != nil || !has {
				e = errors.New("USB_MAC_DAD_PROJECTION_ORIGINAL_UNPROVEN")
			} else {
				for _, dad := range store.DAD {
					if dad.Scope.Role != "mac" {
						continue
					}
					if validateDADProjection(dad.Scope, s) != nil || dad.Scope.LUID != binding.CurrentScope.LUID {
						e = errors.New("USB_MAC_DAD_PROJECTION_SOURCE_CHANGED")
						break
					}
					e = restoreDADZeroForOwnedMappingUnlocked(ctx, dir, dad.Scope, s, next.OriginalSHA256, false, func(original Scope) error {
						if original != dad.Scope || !d.HandleHeld() || d.Index != s.Index || d.LUID != s.LUID || !strings.EqualFold(d.GUID.String(), s.GUID) {
							return errors.New("USB_MAC_DAD_PROJECTION_HANDLE_UNPROVEN")
						}
						got, present, re := readSecondaryBinding(dir)
						if re != nil || !present || got != next {
							return errors.New("USB_MAC_DAD_PROJECTION_JOURNAL_CHANGED")
						}
						if _, re = exactSecondaryOriginal(dir, next); re != nil {
							return re
						}
						return verify()
					})
					break
				}
			}
		}
	}
	finish()
	if e != nil {
		d.Close()
		return nil, nil, true, e
	}
	return d, r, true, nil
}

// BindFactoryDevice attaches only the actual held factory handle whose returned
// mapping is already covered by this private complete session baseline.
func (r *RetainedSecondary) BindFactoryDevice(ctx context.Context, d *wintun.Device) error {
	if r == nil || d == nil || !d.FactoryHandleHeld() || r.device != nil || d.Index != r.scope.Index || d.LUID != r.scope.LUID || !strings.EqualFold(d.GUID.String(), r.scope.GUID) {
		return errors.New("USB_SECONDARY_FACTORY_HANDLE_UNPROVEN")
	}
	if e := r.VerifyAddress(ctx, usbaddress.InterfaceProof{Index: d.Index, LUID: d.LUID, GUID: d.GUID.String()}); e != nil {
		return e
	}
	r.device = d
	return nil
}
func (r *RetainedSecondary) VerifyCleanupAddress(ctx context.Context, p usbaddress.InterfaceProof) error {
	if r == nil || r.scope.Role != "mac" || p.Index != r.scope.Index || p.LUID != r.scope.LUID || !strings.EqualFold(p.GUID, r.scope.GUID) {
		return errors.New("USB_SECONDARY_CLEANUP_SCOPE_UNPROVEN")
	}
	a, e := verifyRetainedRuntime(ctx, r.dir, r.scope, r.localCleanupOwner, WintunProfileOps(r.scope, r.localCleanupOwner, nil), r.baseline.Created, r.baseline.AddressMode)
	if e != nil || a.Scope != r.scope || a.Created != r.baseline.Created || a.ReceiptSHA256 != r.baseline.ReceiptSHA256 {
		return errors.New("USB_SECONDARY_CLEANUP_ADDRESS_UNPROVEN")
	}
	return nil
}

// VerifyOwnedNativeLease is used inside the DAD/configuration transaction. It
// checks this private actual handle and protected completed binding without
// re-entering configMutex. Address/firewall publication still needs VerifyAddress.
func (r *RetainedSecondary) VerifyOwnedNativeLease(ctx context.Context, p usbaddress.InterfaceProof) error {
	if ctx == nil || ctx.Err() != nil || r == nil || r.device == nil || !r.device.HandleHeld() || r.device.Index != p.Index || r.device.LUID != p.LUID || !strings.EqualFold(r.device.GUID.String(), p.GUID) || r.scope != (Scope{Role: "mac", GUID: p.GUID, Index: p.Index, LUID: p.LUID}) {
		return errors.New("USB_SECONDARY_PRIVATE_LEASE_UNPROVEN")
	}
	if e := r.verify(); e != nil {
		return e
	}
	if e := r.localCleanupOwner(); e != nil {
		return e
	}
	v, found, e := readSecondaryBinding(r.dir)
	if e != nil || !found {
		return errors.New("USB_SECONDARY_PRIVATE_BINDING_UNPROVEN")
	}
	_, e = exactSecondaryOriginal(r.dir, v)
	return e
}
