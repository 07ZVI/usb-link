//go:build windows && amd64

package ipadncm

import (
	"errors"
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
	fresh, e := b.capture(p.Node)
	if e != nil || !localPhotoSameOriginal(fresh, p) {
		return errors.New("PHOTO_ORIGINAL_CHANGED")
	}
	set, info, e := exactPortableTarget(p.Node)
	if e != nil {
		return photoWindowsFailure("PHOTO_NATIVE_OWNERSHIP_UNPROVEN", e)
	}
	defer set.Close()
	s := portableNativeObservation(info.DevInst, p.Node)
	if !localPhotoService(set, info) || !s.targetReadBack(p.Value, false) || s.Problem != 0 || s.Status&8 == 0 || s.FlagsAbsent == p.Present || !allowed() {
		return errors.New("PHOTO_DISABLE_CANCELLED_OR_CHANGED")
	}
	cr, _, _ := portableCfg.NewProc("CM_Disable_DevNode").Call(uintptr(info.DevInst), uintptr(portableDisableFlags))
	if cr != 0 {
		return photoNativeFailure("PHOTO_NATIVE_DISABLE_FAILED", "CONFIGRET", uint32(cr), nil)
	}
	return nil
}
