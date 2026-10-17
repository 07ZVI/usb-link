//go:build windows && amd64

package ipadncm

import (
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"sync"
	"syscall"
)

func localPhotoFresh(p portablePropertyOriginal) (portablePhantomProof, PortableNodeObservation, error) {
	if !p.valid() || !localPhotoReceiptValid(p.Node) {
		return portablePhantomProof{}, PortableNodeObservation{}, errors.New("PHOTO_RECEIPT_INVALID")
	}
	proof, s, e := readPortableProperties(p.Node)
	if e != nil || !proof.Unique || !proof.Instance || !proof.Class || !proof.Root || !proof.PresenceReadable || !proof.Setup.same(proof.Registry) || (proof.Registry.Value != p.Value && proof.Registry.Value != p.Value|1) {
		return proof, s, photoFailure("PHOTO_NATIVE_OWNERSHIP_UNPROVEN", photoWindowsFailure("PHOTO_NATIVE_OWNERSHIP_UNPROVEN", e))
	}
	if proof.Absent {
		if proof.StateCR != 13 {
			return proof, s, errors.New("PHOTO_PHANTOM_UNPROVEN")
		}
	} else if s.proofError(p.Value) != nil {
		return proof, s, errors.New("PHOTO_NATIVE_STATE_UNPROVEN")
	}
	return proof, s, nil
}
func restoreLocalPhotoEntry(dir string, p portablePropertyOriginal) error {
	if e := verifyLocalPhotoOwned(dir, p); e != nil {
		return photoWindowsFailure("PHOTO_RESTORE_FAILED", e)
	}
	proof, s, e := localPhotoFresh(p)
	if e != nil {
		return photoWindowsFailure("PHOTO_RESTORE_FAILED", e)
	}
	if !proof.Absent && !s.targetReadBack(p.Value, false) {
		if !s.targetReadBack(p.Value, true) {
			return errors.New("PHOTO_RESTORE_STATE_CHANGED")
		}
		set, info, e := exactPortableTarget(p.Node)
		if e != nil {
			return photoWindowsFailure("PHOTO_RESTORE_FAILED", e)
		}
		now := portableNativeObservation(info.DevInst, p.Node)
		if !localPhotoService(set, info) || !now.targetReadBack(p.Value, true) || verifyLocalPhotoOwned(dir, p) != nil {
			set.Close()
			return errors.New("PHOTO_RESTORE_TARGET_CHANGED")
		}
		cr, _, _ := portableCfg.NewProc("CM_Enable_DevNode").Call(uintptr(info.DevInst), 0)
		set.Close()
		if cr != 0 {
			return photoNativeFailure("PHOTO_NATIVE_ENABLE_FAILED", "CONFIGRET", uint32(cr), nil)
		}
		proof, s, e = localPhotoFresh(p)
		if e != nil || proof.Absent || !s.targetReadBack(p.Value, false) {
			return errors.New("PHOTO_ENABLE_UNCONFIRMED")
		}
	}
	if !proof.Registry.original(p) {
		if e = verifyLocalPhotoOwned(dir, p); e != nil {
			return photoWindowsFailure("PHOTO_RESTORE_FAILED", e)
		}
		before, _, e := localPhotoFresh(p)
		if e != nil {
			return photoWindowsFailure("PHOTO_RESTORE_FAILED", e)
		}
		set, info, e := exactPortableTarget(p.Node)
		if e != nil {
			return photoWindowsFailure("PHOTO_RESTORE_FAILED", e)
		}
		now := portableNativeObservation(info.DevInst, p.Node)
		setup, reg := setupPortableProperty(set, info), registryPortableProperty(set, info)
		identity := now.InstanceMatches && now.ClassMatches && now.RootMatches
		state := before.Absent && now.StateCR == 13 || !before.Absent && now.targetReadBack(p.Value, false)
		if !localPhotoService(set, info) || !identity || !state || !setup.same(reg) || reg != before.Registry {
			set.Close()
			return errors.New("PHOTO_PROPERTY_CHANGED")
		}
		e = setPortableConfigProperty(set, info, &p)
		set.Close()
		if e != nil {
			return photoWindowsFailure("PHOTO_PROPERTY_RESTORE_FAILED", e)
		}
	}
	after, state, e := localPhotoFresh(p)
	if e != nil || !after.Registry.original(p) || (!after.Absent && !state.targetReadBack(p.Value, false)) {
		return errors.New("PHOTO_RESTORE_UNCONFIRMED")
	}
	return nil
}

// Public builds can retire exact local-owned records, but cannot create them.
var localPhotoNativeMutex sync.Mutex

func RestorePhotoIsolation(dir string) error {
	localPhotoNativeMutex.Lock()
	defer localPhotoNativeMutex.Unlock()
	j, e := readLocalPhotoJournal(dir)
	if e != nil {
		return errors.New("PHOTO_JOURNAL_UNREADABLE")
	}
	for len(j.Entries) > 0 {
		if e = restoreLocalPhotoEntry(dir, j.Entries[0]); e != nil {
			return photoWindowsFailure("PHOTO_RESTORE_FAILED", e)
		}
		j.Entries = append([]portablePropertyOriginal(nil), j.Entries[1:]...)
		if e = writeLocalPhotoJournal(dir, j); e != nil {
			return errors.New("PHOTO_JOURNAL_CHECKPOINT_FAILED")
		}
	}
	return nil
}
func localPhotoSameOriginal(a, b portablePropertyOriginal) bool {
	return samePortableReceipt(a.Node, b.Node) && a.Present == b.Present && a.Type == b.Type && a.Size == b.Size && a.Value == b.Value
}

func localPhotoService(set windows.DevInfo, info *windows.DevInfoData) bool {
	v, e := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE)
	if e != nil {
		return false
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	return strings.EqualFold(s, "WUDFWpdMtp") || strings.EqualFold(s, "WUDFRd") || strings.EqualFold(s, "usbscan")
}

func photoWindowsFailure(code string, err error) error {
	if err == nil {
		return nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return photoNativeFailure(code, "WIN32", uint32(errno), err)
	}
	return photoFailure(code, err)
}
