//go:build windows && amd64

package ipadncm

import (
	"encoding/binary"
	"errors"

	"golang.org/x/sys/windows"
)

type localPhotoNativeBackend struct{ dir string }

func (b *localPhotoNativeBackend) load() (localPhotoJournal, error) {
	j, e := readLocalPhotoJournal(b.dir)
	return j, photoWindowsFailure("PHOTO_JOURNAL_UNREADABLE", e)
}
func (b *localPhotoNativeBackend) save(j localPhotoJournal) error {
	return photoWindowsFailure("PHOTO_JOURNAL_SAVE_FAILED", writeLocalPhotoJournal(b.dir, j))
}
func (b *localPhotoNativeBackend) restore(p portablePropertyOriginal) error {
	return restoreLocalPhotoEntry(b.dir, p)
}
func (b *localPhotoNativeBackend) scan(root string) ([]portableNodeReceipt, error) {
	nodes, e := portableNodes(root)
	if e != nil {
		return nil, photoWindowsFailure("PHOTO_SCAN_UNPROVEN", e)
	}
	var result []portableNodeReceipt
	for _, n := range nodes {
		if !localPhotoReceiptValid(n) {
			continue
		}
		set, info, e := exactPortableTarget(n)
		if e != nil {
			return nil, photoWindowsFailure("PHOTO_SCAN_UNPROVEN", e)
		}
		valid := localPhotoService(set, info)
		s := portableNativeObservation(info.DevInst, n)
		set.Close()
		if !valid || s.proofError(n.ConfigFlags) != nil {
			return nil, errors.New("PHOTO_TARGET_UNPROVEN")
		}
		result = append(result, n)
	}
	return result, nil
}
func (b *localPhotoNativeBackend) capture(n portableNodeReceipt) (portablePropertyOriginal, error) {
	p, s, e := readPortableProperties(n)
	if e != nil || p.Absent || !p.PresenceReadable {
		return portablePropertyOriginal{}, photoFailure("PHOTO_ORIGINAL_UNPROVEN", photoWindowsFailure("PHOTO_ORIGINAL_UNPROVEN", e))
	}
	return portableOriginalBeforeDisable(n, s, p.Setup, p.Registry)
}
func (b *localPhotoNativeBackend) disabled(n portableNodeReceipt) (bool, error) {
	p, s, e := readPortableProperties(n)
	if e != nil || p.Absent || !p.Setup.same(p.Registry) || s.proofError(n.ConfigFlags) != nil {
		return false, photoFailure("PHOTO_STATE_UNPROVEN", photoWindowsFailure("PHOTO_STATE_UNPROVEN", e))
	}
	return s.targetReadBack(n.ConfigFlags, true), nil
}
func (b *localPhotoNativeBackend) disable(p portablePropertyOriginal, allowed func() bool) error {
	if verifyLocalPhotoOwned(b.dir, p) != nil {
		return errors.New("PHOTO_JOURNAL_OWNERSHIP_CHANGED")
	}
	set, info, e := exactPortableTarget(p.Node)
	if e != nil {
		return photoWindowsFailure("PHOTO_NATIVE_OWNERSHIP_UNPROVEN", e)
	}
	defer set.Close()
	s := portableNativeObservation(info.DevInst, p.Node)
	if s.ConfigFlags != p.Value|1 {
		// Nothing persisted yet: the live node must still be the captured original.
		fresh, e := b.capture(p.Node)
		if e != nil || !localPhotoSameOriginal(fresh, p) {
			return errors.New("PHOTO_ORIGINAL_CHANGED")
		}
		s = portableNativeObservation(info.DevInst, p.Node)
	}
	if !localPhotoService(set, info) || !localPhotoDisableReady(s, p) || !allowed() {
		return errors.New("PHOTO_DISABLE_CANCELLED_OR_CHANGED")
	}
	cr, _, _ := portableCfg.NewProc("CM_Disable_DevNode").Call(uintptr(info.DevInst), uintptr(portableDisableFlags))
	if cr != 0 {
		return photoNativeFailure("PHOTO_NATIVE_DISABLE_FAILED", "CONFIGRET", uint32(cr), nil)
	}
	return nil
}

func (b *localPhotoNativeBackend) loadKnown() (localPhotoKnown, error) {
	k, e := readLocalPhotoKnown(b.dir)
	return k, photoWindowsFailure("PHOTO_KNOWN_UNREADABLE", e)
}
func (b *localPhotoNativeBackend) saveKnown(k localPhotoKnown) error {
	return photoWindowsFailure("PHOTO_KNOWN_SAVE_FAILED", writeLocalPhotoKnown(b.dir, k))
}

func localPhotoHardwareID(set windows.DevInfo, info *windows.DevInfoData) bool {
	v, e := set.DeviceRegistryProperty(info, windows.SPDRP_HARDWAREID)
	ids, ok := v.([]string)
	return e == nil && ok && localPhotoHardwareMatch(ids)
}

// Read the exact remembered instance from its own properties, whether or not
// it is currently present. Nothing is written; absence of the registration is
// a normal result, any other doubt is reported to the planner as a mismatch.
func (b *localPhotoNativeBackend) probe(k portablePropertyOriginal) (localPhotoProbe, error) {
	var pr localPhotoProbe
	n := k.Node
	set, info, e := exactPortableTarget(n)
	if errors.Is(e, errPortableTargetAbsent) {
		return pr, nil
	}
	if e != nil {
		return pr, photoWindowsFailure("PHOTO_KNOWN_UNPROVEN", e)
	}
	defer set.Close()
	pr.Registered = true
	count, e := portablePresentCount(n)
	if e == nil && count > 1 {
		e = errors.New("portable PRESENT target ambiguous")
	}
	if e != nil {
		return pr, photoWindowsFailure("PHOTO_KNOWN_UNPROVEN", e)
	}
	pr.Present = count == 1
	pr.Setup, pr.Registry = setupPortableProperty(set, info), registryPortableProperty(set, info)
	pr.Service, pr.Hardware = localPhotoService(set, info), localPhotoHardwareID(set, info)
	fresh := n
	fresh.ConfigFlags, fresh.OriginalDisabled = pr.Registry.Value, pr.Registry.Value&1 != 0
	s := portableNativeObservation(info.DevInst, fresh)
	pr.Instance, pr.Class, pr.Root = s.InstanceMatches, s.ClassMatches, s.RootMatches
	if s.StateReadable {
		pr.Problem = s.Problem
	}
	if pr.Registry.Value&1 == 0 && pr.Setup.same(pr.Registry) && pr.Instance && pr.Class && pr.Root {
		var o portablePropertyOriginal
		if pr.Present {
			o, e = portableOriginalBeforeDisable(fresh, s, pr.Setup, pr.Registry)
		} else if s.StateCR == 13 {
			o, e = localPhotoPhantomOriginal(fresh, pr.Setup, pr.Registry)
		} else {
			e = errors.New("PHOTO_ORIGINAL_UNPROVEN")
		}
		if e == nil {
			pr.Original = &o
		}
	}
	return pr, nil
}

func (b *localPhotoNativeBackend) disableKnown(p portablePropertyOriginal, allowed func() bool) error {
	if verifyLocalPhotoOwned(b.dir, p) != nil {
		return errors.New("PHOTO_JOURNAL_OWNERSHIP_CHANGED")
	}
	count, e := portablePresentCount(p.Node)
	if e == nil && count > 1 {
		e = errors.New("portable PRESENT target ambiguous")
	}
	if e != nil {
		return photoWindowsFailure("PHOTO_NATIVE_OWNERSHIP_UNPROVEN", e)
	}
	if count == 1 {
		return b.disable(p, allowed)
	}
	// Not present: the persisted ConfigFlags is the only state there is. Every
	// identity fact is read again from the instance immediately before the write.
	set, info, e := exactPortableTarget(p.Node)
	if e != nil {
		return photoWindowsFailure("PHOTO_NATIVE_OWNERSHIP_UNPROVEN", e)
	}
	defer set.Close()
	s := portableNativeObservation(info.DevInst, p.Node)
	setup, reg := setupPortableProperty(set, info), registryPortableProperty(set, info)
	if !s.InstanceMatches || !s.ClassMatches || !s.RootMatches || s.StateCR != 13 || !localPhotoService(set, info) || !localPhotoHardwareID(set, info) || !setup.same(reg) || reg.Value != p.Value && reg.Value != p.Value|1 || !allowed() {
		return errors.New("PHOTO_DISABLE_CANCELLED_OR_CHANGED")
	}
	if reg.Value == p.Value|1 {
		return nil
	}
	var v [4]byte
	binary.LittleEndian.PutUint32(v[:], p.Value|1)
	if e = windows.SetupDiSetDeviceRegistryProperty(set, info, windows.SPDRP_CONFIGFLAGS, v[:]); e != nil {
		return photoWindowsFailure("PHOTO_NATIVE_DISABLE_FAILED", e)
	}
	return nil
}

func (b *localPhotoNativeBackend) disabledKnown(p portablePropertyOriginal) (bool, error) {
	proof, _, e := readPortableProperties(p.Node)
	if e != nil || !proof.Unique || !proof.PresenceReadable {
		return false, photoFailure("PHOTO_STATE_UNPROVEN", photoWindowsFailure("PHOTO_STATE_UNPROVEN", e))
	}
	if !proof.Absent {
		return b.disabled(p.Node)
	}
	return proof.Instance && proof.Class && proof.Root && proof.StateCR == 13 && proof.Setup.same(proof.Registry) && proof.Registry.Present && proof.Registry.Value == p.Value|1, nil
}
