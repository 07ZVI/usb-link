//go:build windows && amd64

package usbhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/wintun"
	"time"
)

var errPersistentFactoryCreate = errors.New("USB_HOST_PERSISTENT_FACTORY_CREATE_REQUIRED")

func exactHostFactoryOriginal(dir string, v persistentFactory) error {
	o, found, e := interfaceconfig.ReadPersistentOriginalSnapshot(dir, "host")
	if e != nil || !found || o.SHA256 != v.OriginalSHA256 || o.ImmutableScope != v.OriginalScope || o != v.Original || !o.AddressAbsent || o.Address != "10.6.9.1" || o.Prefix != 32 {
		return errors.New("USB_HOST_FACTORY_ORIGINAL_CHANGED")
	}
	return nil
}
func factoryProofCreated(mode string, created int64) int64 {
	if mode == "persistent" {
		return 0
	}
	return created
}
func factoryRecordCurrent(dir string, v persistentFactory) error {
	if e := factoryNoLegacyIntent(dir); e != nil {
		return e
	}
	got, found, e := readPersistentFactory(dir)
	if e != nil || !found || got != v {
		return errors.New("USB_HOST_FACTORY_RECORD_CHANGED")
	}
	b, _, e := readPersistentFactoryJournal(dir)
	if e != nil {
		return e
	}
	_, e = persistentFactoryJournalPosition(v, b)
	return e
}
func factoryNative(v persistentFactory, index uint32, luid uint64) error {
	return netconfig.VerifySharedHostRecreatedNative(index, luid, v.Instance)
}
func factoryProfile(s interfaceconfig.Scope, owner func() error) interfaceconfig.ProfileOps {
	return interfaceconfig.WintunProfileOps(s, owner, log.New(os.Stderr, "USB host factory: ", 0))
}
func capturePersistentHostFactory(ctx context.Context, dir string, p journal, d *wintun.Device) (result error) {
	endPhase := persistentFactoryPhase("capture")
	defer func() { endPhase(result) }()
	if d == nil || !d.FactoryHandleHeld() || d.Index != p.Index || d.LUID != p.LUID || p.Version != 2 {
		return errors.New("USB_HOST_FACTORY_HANDLE_REQUIRED")
	}
	b, got, e := readPersistentFactoryJournal(dir)
	if e != nil || got != p {
		return errors.New("USB_HOST_FACTORY_JOURNAL_CHANGED")
	}
	o, found, e := interfaceconfig.ReadPersistentOriginalSnapshot(dir, "host")
	if e != nil || !found || o.SHA256 != p.PersistentSHA256 || o.ImmutableScope != hostScope(p) {
		return errors.New("USB_HOST_FACTORY_ORIGINAL_UNPROVEN")
	}
	instance, e := netconfig.CaptureSharedHostHealthyNative(p.Index, p.LUID)
	if e != nil {
		return e
	}
	v := persistentFactory{Version: 1, OriginalSHA256: o.SHA256, OriginalScope: o.ImmutableScope, Original: o, JournalSHA256: journalDigest(b), Source: p, Instance: instance, State: "ready"}
	owner := func() error {
		fresh, q, e := readPersistentFactoryJournal(dir)
		if e != nil || q != p || journalDigest(fresh) != v.JournalSHA256 {
			return errors.New("USB_HOST_FACTORY_JOURNAL_CHANGED")
		}
		return factoryNative(v, p.Index, p.LUID)
	}
	return interfaceconfig.WithPersistentHostFactoryProof(ctx, dir, hostScope(p), v.OriginalSHA256, p.AddressMode, factoryProofCreated(p.AddressMode, p.Created), owner, factoryProfile(hostScope(p), owner), func(a interfaceconfig.ActiveOwnership) error {
		if a.Scope != hostScope(p) || a.Created != p.Created || a.AddressMode != p.AddressMode || a.ReceiptSHA256 != p.PersistentSHA256 {
			return errors.New("USB_HOST_FACTORY_CAPTURE_PROOF_CHANGED")
		}
		old, found, e := readPersistentFactory(dir)
		if e != nil {
			return e
		}
		if found {
			if old != v {
				return errors.New("USB_HOST_FACTORY_CAPTURE_EXISTS")
			}
			return nil
		}
		return writePersistentFactory(dir, v, nil)
	})
}
func factoryProveAndCommit(ctx context.Context, dir string, v persistentFactory, index uint32, luid uint64, mode string, created int64) (out journal, result error) {
	endPhase := persistentFactoryPhase("proof_checkpoint")
	defer func() { endPhase(result) }()
	s := hostScope(v.Source)
	s.Index = index
	s.LUID = luid
	owner := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := factoryRecordCurrent(dir, v); e != nil {
			return e
		}
		return factoryNative(v, index, luid)
	}
	var next journal
	e := interfaceconfig.WithPersistentHostFactoryProof(ctx, dir, s, v.OriginalSHA256, mode, factoryProofCreated(mode, created), owner, factoryProfile(s, owner), func(a interfaceconfig.ActiveOwnership) error {
		if a.Scope != s || a.ReceiptSHA256 != v.OriginalSHA256 || a.AddressMode != mode || a.Created <= 0 {
			return errors.New("USB_HOST_FACTORY_ACTIVE_PROOF_CHANGED")
		}
		next = v.Source
		next.Index = index
		next.LUID = luid
		next.Created = a.Created
		next.AddressMode = a.AddressMode
		proved := v
		proved.State = "proved"
		proved.MappedIndex = index
		proved.MappedLUID = luid
		proved.Next = next
		if v.State == "proved" {
			if proved != v {
				return errors.New("USB_HOST_FACTORY_PROVED_MAPPING_CHANGED")
			}
		} else if e := writePersistentFactory(dir, proved, &v); e != nil {
			return e
		}
		if e := factoryNative(proved, index, luid); e != nil {
			return e
		}
		if e := checkpointFactoryJournal(dir, proved); e != nil {
			return e
		}
		if e := factoryNative(proved, index, luid); e != nil {
			return e
		}
		ready := proved
		ready.State = "ready"
		ready.Source = next
		ready.JournalSHA256 = journalDigestJSON(next)
		ready.Attempt = ""
		ready.Ticks = 0
		ready.MappedIndex = 0
		ready.MappedLUID = 0
		ready.Next = journal{}
		if e := writePersistentFactory(dir, ready, &proved); e != nil {
			return e
		}
		v = ready
		return nil
	})
	return next, e
}

// Recovery never invokes a native creator. A known nonpresent/full absence
// returns a distinct request to Start; unknown calls stay behind a reboot AND
// complete installed/MIB/address absence fence.
func recoverPersistentHostFactory(ctx context.Context, dir string, v persistentFactory) (result error) {
	endPhase := persistentFactoryPhase("recovery")
	defer func() {
		if result == errPersistentFactoryCreate || result == errOwnedPersistentOpen {
			endPhase(nil)
		} else {
			endPhase(result)
		}
	}()
	if v.State == "restore_attempt" || v.State == "restore_mapped" {
		return recoverPersistentRestoreFactory(ctx, dir, v)
	}
	if factoryRestoreMappedPhase(v.State) {
		return finishPersistentHostRemoval(ctx, dir, v)
	}
	if v.State == "restoring" {
		if e := finishPersistentHostOriginalRestore(ctx, dir, v); e != nil {
			return e
		}
		next, found, e := readPersistentFactory(dir)
		if e != nil || !found {
			return errors.New("USB_HOST_FACTORY_RESTORE_BINDING_UNPROVEN")
		}
		return finishPersistentHostRemoval(ctx, dir, next)
	}
	if v.State == "stopped" || v.State == "removing" || v.State == "removed" || v.State == "removal_unknown" || v.State == "removal_restart" {
		return finishPersistentHostRemoval(ctx, dir, v)
	}
	requested, re := interfaceconfig.PersistentRestoreRequested(dir)
	if re != nil {
		return re
	}
	if requested {
		if v.State != "ready" && v.State != "closed" {
			return errors.New("USB_HOST_FACTORY_RESTORE_UNKNOWN_PHASE")
		}
		restoring, e := beginPersistentHostOriginalRestore(dir, v)
		if e != nil {
			return e
		}
		return recoverPersistentHostFactory(ctx, dir, restoring)
	}
	if !interfaceconfig.PersistentEnabled() {
		return errors.New("USB_HOST_PERSISTENT_OPTION_DISABLED")
	}
	if e := exactHostFactoryOriginal(dir, v); e != nil {
		return e
	}
	if e := factoryRecordCurrent(dir, v); e != nil {
		return e
	}
	if v.State == "attempt" {
		ticks := systemTicks()
		if ticks == 0 || ticks >= v.Ticks {
			return errors.New("USB_HOST_FACTORY_UNKNOWN_CALL_RESTART_REQUIRED")
		}
		absent, e := netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
		rows, re := recoveryAddresses(0, v.Source.LUID)
		if e != nil || !absent || re != nil || len(rows) != 0 {
			return errors.New("USB_HOST_FACTORY_UNKNOWN_CALL_ABSENCE_UNPROVEN")
		}
		if e = factoryRecordCurrent(dir, v); e != nil {
			return e
		}
		if e = exactHostFactoryOriginal(dir, v); e != nil {
			return e
		}
		closed := v
		closed.State = "closed"
		closed.Attempt = ""
		closed.Ticks = 0
		if e = writePersistentFactory(dir, closed, &v); e != nil {
			return e
		}
		return errPersistentFactoryCreate
	}
	if v.State == "mapped" {
		var pe error
		v, pe = projectPersistentFactoryMapped(dir, v)
		if pe != nil {
			return pe
		}
		// This exact returned mapping was checkpointed after fixed-GUID and unique
		// installed-node readback. It cannot adopt a different live LUID.
		_, e := factoryProveAndCommit(ctx, dir, v, v.MappedIndex, v.MappedLUID, "persistent", 0)
		if e != nil {
			absent, ae := netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
			oldRows, oe := recoveryAddresses(0, v.Source.LUID)
			newRows, ne := recoveryAddresses(0, v.MappedLUID)
			if ae != nil || oe != nil || ne != nil || persistentFactoryUnknownAbsent(v, systemTicks(), absent, len(oldRows), len(newRows)) != nil {
				return e
			}
			if e = factoryRecordCurrent(dir, v); e != nil {
				return e
			}
			if e = exactHostFactoryOriginal(dir, v); e != nil {
				return e
			}
			closed := v
			closed.State = "closed"
			closed.Attempt = ""
			closed.Ticks = 0
			closed.MappedIndex = 0
			closed.MappedLUID = 0
			if e = writePersistentFactory(dir, closed, &v); e != nil {
				return e
			}
			return errPersistentFactoryCreate
		}
		return errOwnedPersistentOpen
	}
	if v.State == "proved" {
		e := finishPersistentFactoryProved(ctx, dir, v)
		if e == nil {
			ready, found, re := readPersistentFactory(dir)
			if re != nil || !found {
				return errors.New("USB_HOST_FACTORY_READY_READBACK_UNPROVEN")
			}
			return recoverPersistentHostFactory(ctx, dir, ready)
		}
		// A creator can die after ready proof but before publication. Only its
		// saved returned native identity, with complete nonpresence, may retire
		// this exact known result into the next closed obligation.
		if netconfig.VerifySharedHostFactorySourceNative(v.Next.Index, v.Next.LUID, v.Instance) != nil {
			return e
		}
		if e = factoryRecordCurrent(dir, v); e != nil {
			return e
		}
		if e = checkpointFactoryJournal(dir, v); e != nil {
			return e
		}
		ready := v
		ready.State = "ready"
		ready.Source = v.Next
		ready.JournalSHA256 = journalDigestJSON(v.Next)
		ready.Attempt = ""
		ready.Ticks = 0
		ready.MappedIndex = 0
		ready.MappedLUID = 0
		ready.Next = journal{}
		if e = writePersistentFactory(dir, ready, &v); e != nil {
			return e
		}
		closed := ready
		closed.State = "closed"
		if e = writePersistentFactory(dir, closed, &ready); e != nil {
			return e
		}
		return errPersistentFactoryCreate
	}
	if v.State == "closed" {
		// Close already relinquished the creator. A transient healthy node is
		// not a stopped result and must not be reopened while PnP retirement
		// is pending. Only exact native source nonpresence permits a creator.
		if e := netconfig.VerifySharedHostFactorySourceNative(v.Source.Index, v.Source.LUID, v.Instance); e != nil {
			return errors.New("USB_HOST_FACTORY_CLOSE_SETTLE_PENDING")
		}
		if e := factoryRecordCurrent(dir, v); e != nil {
			return e
		}
		if e := exactHostFactoryOriginal(dir, v); e != nil {
			return e
		}
		return errPersistentFactoryCreate
	}
	// A new healthy incarnation sharing only the GUID is forbidden. Existing
	// successful ownership admits a reboot index change only at the same LUID.
	r, present, e := findHost()
	if e != nil {
		return e
	}
	if present && r.InterfaceLuid == v.Source.LUID && factoryNative(v, r.InterfaceIndex, r.InterfaceLuid) == nil {
		mode := v.Source.AddressMode
		created := v.Source.Created
		ip := row(journal{Index: r.InterfaceIndex, LUID: r.InterfaceLuid})
		if windows.GetUnicastIpAddressEntry(&ip) == nil && ip.ValidLifetime == 0xffffffff && ip.PreferredLifetime == 0xffffffff {
			mode = "persistent"
			created = 0
		}
		_, e = factoryProveAndCommit(ctx, dir, v, r.InterfaceIndex, r.InterfaceLuid, mode, created)
		if e != nil {
			return e
		}
		return errOwnedPersistentOpen
	}
	if e = netconfig.VerifySharedHostFactorySourceNative(v.Source.Index, v.Source.LUID, v.Instance); e != nil {
		return e
	}
	if e = factoryRecordCurrent(dir, v); e != nil {
		return e
	}
	if e = exactHostFactoryOriginal(dir, v); e != nil {
		return e
	}
	if v.State == "ready" {
		closed := v
		closed.State = "closed"
		if e = writePersistentFactory(dir, closed, &v); e != nil {
			return e
		}
	}
	return errPersistentFactoryCreate
}
func preparePersistentHostFactory(ctx context.Context, dir, dll string) (device *wintun.Device, out journal, result error) {
	endPhase := persistentFactoryPhase("create")
	defer func() { endPhase(result) }()
	old, found, e := readPersistentFactory(dir)
	if e != nil || !found || old.State != "closed" {
		return nil, journal{}, errors.New("USB_HOST_FACTORY_CLOSED_REQUIRED")
	}
	beforeOld := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := factoryRecordCurrent(dir, old); e != nil {
			return e
		}
		if e := exactHostFactoryOriginal(dir, old); e != nil {
			return e
		}
		return netconfig.VerifySharedHostFactorySourceNative(old.Source.Index, old.Source.LUID, old.Instance)
	}
	if e = beforeOld(); e != nil {
		return nil, journal{}, e
	}
	pin, e := netconfig.PinVerifiedWintunNative(dll, log.New(os.Stderr, "USB host factory: ", 0))
	if e != nil {
		return nil, journal{}, e
	}
	defer pin.Close()
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return nil, journal{}, e
	}
	attempt := old
	attempt.State = "attempt"
	attempt.Attempt = hex.EncodeToString(nonce[:])
	attempt.Ticks = systemTicks()
	if attempt.Ticks == 0 {
		return nil, journal{}, errors.New("USB_HOST_FACTORY_COUNTER_UNPROVEN")
	}
	if e = writePersistentFactory(dir, attempt, &old); e != nil {
		return nil, journal{}, e
	}
	before := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := factoryRecordCurrent(dir, attempt); e != nil {
			return e
		}
		if e := exactHostFactoryOriginal(dir, attempt); e != nil {
			return e
		}
		return netconfig.VerifySharedHostFactorySourceNative(old.Source.Index, old.Source.LUID, old.Instance)
	}
	observation := wintun.OwnedCreateObservation{}
	d, e := wintun.CreateOwnedNonpresentHost(dll, before, &observation)
	if e != nil {
		if !observation.Called && before() == nil {
			closed := attempt
			closed.State = "closed"
			closed.Attempt = ""
			closed.Ticks = 0
			_ = writePersistentFactory(dir, closed, &attempt)
		}
		return nil, journal{}, e
	}
	ok := false
	defer func() {
		if !ok {
			d.Close()
		}
	}()
	if !observation.Called || !observation.Returned || !observation.Succeeded || !observation.FixedGUIDVerified || observation.Index != d.Index || observation.LUID != d.LUID || !d.FactoryHandleHeld() || factoryNative(old, d.Index, d.LUID) != nil {
		return nil, journal{}, errors.New("USB_HOST_FACTORY_RETURN_UNPROVEN")
	}
	mapped := attempt
	mapped.State = "mapped"
	mapped.MappedIndex = d.Index
	mapped.MappedLUID = d.LUID
	if e = writePersistentFactory(dir, mapped, &attempt); e != nil {
		return nil, journal{}, e
	}
	ownedMapping := old.Source
	ownedMapping.Index = d.Index
	ownedMapping.LUID = d.LUID
	if e = factoryRecordCurrent(dir, mapped); e != nil {
		return nil, journal{}, e
	}
	if e = factoryNative(mapped, d.Index, d.LUID); e != nil {
		return nil, journal{}, e
	}
	if e = prepareHostFlags(ctx, ownedMapping); e != nil {
		return nil, journal{}, e
	}
	if e = factoryNative(mapped, d.Index, d.LUID); e != nil {
		return nil, journal{}, e
	}
	// An interrupted old DAD setting is an immutable obligation, never a
	// reason to adopt a new mapping. Restore it only to this held official
	// return after binding the old saved LUID to the protected source.
	dadOriginal, dadFound, de := interfaceconfig.ReadDADOriginalScope(dir, "host")
	if de != nil {
		return nil, journal{}, de
	}
	if dadFound {
		if dadOriginal.LUID != old.Source.LUID || dadOriginal.Role != "host" || dadOriginal.GUID != old.Source.GUID {
			return nil, journal{}, errors.New("USB_HOST_FACTORY_DAD_SOURCE_CHANGED")
		}
		current := hostScope(old.Source)
		current.Index = d.Index
		current.LUID = d.LUID
		verifyFactory := func(protectedOriginal interfaceconfig.Scope) error {
			if protectedOriginal != dadOriginal || protectedOriginal.LUID != old.Source.LUID || !d.FactoryHandleHeld() || d.Index != mapped.MappedIndex || d.LUID != mapped.MappedLUID {
				return errors.New("USB_HOST_FACTORY_DAD_HANDLE_UNPROVEN")
			}
			if e := factoryRecordCurrent(dir, mapped); e != nil {
				return e
			}
			return factoryNative(mapped, d.Index, d.LUID)
		}
		if e = interfaceconfig.RestoreDADZeroForOwnedFactory(ctx, dir, dadOriginal, current, mapped.OriginalSHA256, verifyFactory); e != nil {
			return nil, journal{}, e
		}
	}
	// PersistentStore may have created the active row before userspace resumes.
	// No finite-row Create or zero-address destructor is legal in this branch.
	var p journal
	// Provider/DAD activation may follow the synchronous creator by a short
	// interval. Retry read-only full proofs while retaining this exact handle,
	// original lease and mapped receipt; never overlap another native creator.
	for i := 0; i < 30; i++ {
		if !d.FactoryHandleHeld() || factoryRecordCurrent(dir, mapped) != nil {
			return nil, journal{}, errors.New("USB_HOST_FACTORY_MAPPED_HANDLE_CHANGED")
		}
		p, e = factoryProveAndCommit(ctx, dir, mapped, d.Index, d.LUID, "persistent", 0)
		if e == nil {
			break
		}
		got, found, re := readPersistentFactory(dir)
		if re != nil || !found || got != mapped {
			return nil, journal{}, e
		}
		select {
		case <-ctx.Done():
			return nil, journal{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if e != nil {
		return nil, journal{}, e
	}
	ok = true
	return d, p, nil
}
func markPersistentHostFactoryClosed(ctx context.Context, dir string, p journal, d *wintun.Device) (result error) {
	endPhase := persistentFactoryPhase("close_checkpoint")
	defer func() { endPhase(result) }()
	if !d.FactoryHandleHeld() {
		return nil
	} // Open-only handles do not own PnP retirement.
	v, found, e := readPersistentFactory(dir)
	if e != nil || !found || v.State != "ready" || v.Source != p || d.Index != p.Index || d.LUID != p.LUID {
		return errors.New("USB_HOST_FACTORY_CLOSE_BINDING_UNPROVEN")
	}
	if e = exactHostFactoryOriginal(dir, v); e != nil {
		return e
	}
	if e = factoryRecordCurrent(dir, v); e != nil {
		return e
	}
	owner := func() error {
		if e := factoryRecordCurrent(dir, v); e != nil {
			return e
		}
		return factoryNative(v, p.Index, p.LUID)
	}
	return interfaceconfig.WithPersistentHostFactoryProof(ctx, dir, hostScope(p), v.OriginalSHA256, p.AddressMode, factoryProofCreated(p.AddressMode, p.Created), owner, factoryProfile(hostScope(p), owner), func(a interfaceconfig.ActiveOwnership) error {
		if a.Created != p.Created || a.ReceiptSHA256 != p.PersistentSHA256 {
			return errors.New("USB_HOST_FACTORY_CLOSE_ACTIVE_CHANGED")
		}
		closed := v
		closed.State = "closed"
		if e := writePersistentFactory(dir, closed, &v); e != nil {
			return e
		}
		v = closed
		return nil
	})
}

// Existing ready ownership may project only a boot-local index, never LUID.
// Consume the old DAD original after exact original-value restoration before
// a subsequent Apply may capture the fresh index as a new local obligation.
func restoreReadyHostDADProjection(ctx context.Context, dir string, p journal) error {
	old, found, e := interfaceconfig.ReadDADOriginalScope(dir, "host")
	if e != nil || !found {
		return e
	}
	current := hostScope(p)
	if old == current {
		return nil
	}
	v, present, e := readPersistentFactory(dir)
	if e != nil || !present || v.State != "ready" || v.Source != p || old.Role != "host" || old.GUID != p.GUID || old.LUID != p.LUID {
		return errors.New("USB_HOST_FACTORY_DAD_READY_SOURCE_UNPROVEN")
	}
	if e = exactHostFactoryOriginal(dir, v); e != nil {
		return e
	}
	owner := func(actualOriginal interfaceconfig.Scope) error {
		if actualOriginal != old || actualOriginal.LUID != p.LUID {
			return errors.New("USB_HOST_FACTORY_DAD_PROJECTION_CHANGED")
		}
		if e := factoryRecordCurrent(dir, v); e != nil {
			return e
		}
		return factoryNative(v, p.Index, p.LUID)
	}
	return interfaceconfig.RestoreDADZeroForOwnedProjection(ctx, dir, old, current, v.OriginalSHA256, owner)
}

// The returned LUID was durably observed only after official Create and exact
// fixed GUID/installed-instance verification. A reboot may renumber its index;
// this projection cannot confer a new LUID or an address creation stamp.
func projectPersistentFactoryMapped(dir string, v persistentFactory) (persistentFactory, error) {
	r, present, e := findHost()
	if e != nil {
		return v, e
	}
	if !present || r.InterfaceLuid != v.MappedLUID || r.InterfaceIndex == v.MappedIndex {
		return v, nil
	}
	if e = factoryRecordCurrent(dir, v); e != nil {
		return v, e
	}
	if e = exactHostFactoryOriginal(dir, v); e != nil {
		return v, e
	}
	if e = factoryNative(v, r.InterfaceIndex, r.InterfaceLuid); e != nil {
		return v, e
	}
	projected := v
	projected.MappedIndex = r.InterfaceIndex
	if e = writePersistentFactory(dir, projected, &v); e != nil {
		return v, e
	}
	if e = factoryNative(projected, r.InterfaceIndex, r.InterfaceLuid); e != nil {
		return projected, e
	}
	return projected, nil
}

// Finish the exact already-proved journal checkpoint first, even when a reboot
// changed the index/stamp. Fresh same-returned-LUID Store/active proof is still
// required; publication waits for the subsequent complete-journal rebind.
func finishPersistentFactoryProved(ctx context.Context, dir string, v persistentFactory) error {
	if v.State != "proved" {
		return errors.New("USB_HOST_FACTORY_PROVED_REQUIRED")
	}
	r, present, e := findHost()
	if e != nil || !present || r.InterfaceLuid != v.Next.LUID {
		return errors.New("USB_HOST_FACTORY_PROVED_MAPPING_UNPROVEN")
	}
	s := hostScope(v.Next)
	s.Index = r.InterfaceIndex
	owner := func() error {
		if e := factoryRecordCurrent(dir, v); e != nil {
			return e
		}
		return factoryNative(v, s.Index, s.LUID)
	}
	return interfaceconfig.WithPersistentHostFactoryProof(ctx, dir, s, v.OriginalSHA256, v.Next.AddressMode, factoryProofCreated(v.Next.AddressMode, v.Next.Created), owner, factoryProfile(s, owner), func(a interfaceconfig.ActiveOwnership) error {
		if a.Scope != s || a.ReceiptSHA256 != v.OriginalSHA256 {
			return errors.New("USB_HOST_FACTORY_PROVED_ACTIVE_CHANGED")
		}
		if e := checkpointFactoryJournal(dir, v); e != nil {
			return e
		}
		ready := v
		ready.State = "ready"
		ready.Source = v.Next
		ready.JournalSHA256 = journalDigestJSON(v.Next)
		ready.Attempt = ""
		ready.Ticks = 0
		ready.MappedIndex = 0
		ready.MappedLUID = 0
		ready.Next = journal{}
		if e := writePersistentFactory(dir, ready, &v); e != nil {
			return e
		}
		v = ready
		return nil
	})
}
