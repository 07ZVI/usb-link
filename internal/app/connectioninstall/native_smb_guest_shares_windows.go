//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"suhang/usbnet/internal/sharing/fileshare"
	"unsafe"
)

// The native share journal approves both sides of an interrupted Guest ACL
// change. No unrelated descriptor, marker, path or account SID is accepted.
func updateNativeGuestShares(guest string) error {
	nativeSMBMu.Lock()
	defer nativeSMBMu.Unlock()
	defer invalidateNativeSMB()
	c, e := loadNativeSMB()
	if e != nil {
		return e
	}
	return updateNativeGuestSharesLocked(&c, guest)
}
func updateNativeGuestSharesLocked(c *nativeSMBConfiguration, guest string) error {
	cat, e := ShareCatalog()
	if e != nil {
		return e
	}
	folders := map[string]fileshare.Folder{}
	for _, f := range cat.List() {
		folders[f.ID] = f
	}
	var failures []error
	for i := range c.Shares {
		s := c.Shares[i]
		got, free, rc, e := getNativeShare(s.Name)
		if e != nil {
			failures = append(failures, e)
			continue
		}
		exists := rc == 0
		if exists && !ownedNativeShare(s, got) {
			free()
			failures = append(failures, fmt.Errorf("NATIVE_SMB_CHANGED_IN_WINDOWS: %s；可選擇交由 Windows 管理", s.Name))
			continue
		}
		if !exists && rc != 2310 {
			failures = append(failures, fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc))
			continue
		}
		targetDescriptor := false
		if exists {
			wanted := s
			wanted.GuestSID = guest
			sd, err := nativeShareSD(wanted)
			targetDescriptor = err == nil && sameNativeSMBShareACL(got.SD, sd)
		}
		atPendingTarget := false
		if exists && s.GuestUpdate {
			wanted := s
			wanted.GuestSID = s.NextGuestSID
			sd, err := nativeShareSD(wanted)
			atPendingTarget = err == nil && sameNativeSMBShareACL(got.SD, sd)
		}
		currentGuest, update := planSMBGuestChange(s.GuestSID, s.NextGuestSID, guest, s.GuestUpdate, atPendingTarget)
		if free != nil {
			free()
		}
		if !update {
			continue
		}
		if s.AccessUpdate {
			return fmt.Errorf("NATIVE_SMB_ACCESS_RECOVERY_REQUIRED")
		}
		// Do not clear an interrupted journal merely because the network ACL
		// matches: the folder ACL may still be on the other side of the change.
		// Publish the new plan atomically, including when the user reverses it.
		s.GuestSID = currentGuest
		staged := s
		staged.GuestUpdate, staged.NextGuestSID = true, guest
		c.Shares[i] = staged
		if e = saveNativeSMB(*c); e != nil {
			return errors.Join(errors.Join(failures...), e)
		}
		target := s
		target.GuestSID, target.GuestUpdate, target.NextGuestSID = guest, false, ""
		sids := []string{}
		var grantError error
		account, err := loadSMBAccount()
		if err == nil && account.SID == s.SID {
			sids = append(sids, s.SID)
		} else if err != nil && !os.IsNotExist(err) {
			grantError = err
		} else if err == nil {
			grantError = fmt.Errorf("SMB_ACCOUNT_IDENTITY_CHANGED")
		}
		if guest != "" {
			sids = append(sids, guest)
		}
		journalError := false
		e = changeSMBGuestPermissions(guest == "", func() error {
			f, ok := folders[s.ID]
			if !ok || !f.Available || !strings.EqualFold(filepath.Clean(f.Path), filepath.Clean(s.Path)) {
				return fmt.Errorf("共享資料夾不可用或身份改變：%s", s.Name)
			}
			if grantError != nil {
				return grantError
			}
			return updateSMBRootGrants(s.ID, s.Path, sids, true)
		}, func() error {
			if !exists || targetDescriptor {
				return nil
			}
			return setNativeShareGuestACL(staged, target)
		}, func() error { c.Shares[i] = target; err := saveNativeSMB(*c); journalError = err != nil; return err })
		if e != nil {
			failures = append(failures, e)
			if journalError {
				return errors.Join(failures...)
			}
			continue
		}

	}
	return errors.Join(failures...)
}
func setNativeShareGuestACL(expected, target nativeSMBShare) error {
	got, free, rc, e := getNativeShare(expected.Name)
	if e != nil {
		return e
	}
	if rc != 0 {
		return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
	}
	owned := ownedNativeShare(expected, got)
	free()
	if !owned {
		return fmt.Errorf("NATIVE_SMB_CHANGED_IN_WINDOWS: %s", expected.Name)
	}
	sd, e := nativeShareSD(target)
	if e != nil {
		return e
	}
	info := struct {
		Reserved uint32
		SD       *windows.SECURITY_DESCRIPTOR
	}{SD: sd}
	proc := nativeNet.NewProc("NetShareSetInfo")
	if e = proc.Find(); e != nil {
		return e
	}
	var field uint32
	result, _, _ := proc.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(target.Name))), 1501, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&field)))
	runtime.KeepAlive(sd)
	runtime.KeepAlive(info)
	if result != 0 {
		return fmt.Errorf("NATIVE_SMB_GUEST_UPDATE_FAILED: %d field=%d", result, field)
	}
	got, free, rc, e = getNativeShare(target.Name)
	if e != nil {
		return e
	}
	if rc != 0 {
		return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
	}
	defer free()
	if !ownedNativeShare(target, got) {
		return fmt.Errorf("NATIVE_SMB_GUEST_READBACK_CHANGED")
	}
	return nil
}
