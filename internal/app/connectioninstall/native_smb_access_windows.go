//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"net/url"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"suhang/usbnet/internal/sharing/fileshare"
	"unsafe"
)

func nativeShareSD(s nativeSMBShare) (*windows.SECURITY_DESCRIPTOR, error) {
	text := "D:P"
	for _, principal := range []struct{ sid, access string }{{s.SID, s.AccountAccess}, {s.GuestSID, s.GuestAccess}} {
		if principal.sid == "" {
			continue
		}
		if _, err := windows.StringToSid(principal.sid); err != nil {
			return nil, err
		}
		mask, err := smbAccessMask(principal.access)
		if err != nil {
			return nil, err
		}
		if mask != "" {
			text += "(A;;" + mask + ";;;" + principal.sid + ")"
		}
	}
	return windows.SecurityDescriptorFromString(text)
}

// The installer comparator rejects empty ACLs. A native share intentionally
// denying both principals needs a protected allocated empty ACL, never NULL.
func sameNativeSMBShareACL(actual, wanted *windows.SECURITY_DESCRIPTOR) bool {
	if actual == nil || wanted == nil {
		return false
	}
	w, _, e := wanted.DACL()
	if e != nil || w == nil {
		return false
	}
	if w.AceCount != 0 {
		return sameACL(actual, wanted)
	}
	a, _, e := actual.DACL()
	if e != nil || a == nil || a.AceCount != 0 {
		return false
	}
	c, _, e := actual.Control()
	return e == nil && c&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) == windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED
}

// Changing the share DACL limits SMB access without rewriting NTFS trees.
// The original/target receipt is durable before NetShareSetInfo; both exact
// descriptors are recognized during recovery, never an external Windows edit.
func UpdateNativeSMBAccess(id, accountAccess, guestAccess string) error {
	if accountAccess == "" || guestAccess == "" || !validSMBAccess(accountAccess) || !validSMBAccess(guestAccess) {
		return fmt.Errorf("NATIVE_SMB_ACCESS_INVALID")
	}
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	nativeSMBMu.Lock()
	defer nativeSMBMu.Unlock()
	defer invalidateNativeSMB()
	c, err := loadNativeSMB()
	if err != nil {
		return err
	}
	for i, s := range c.Shares {
		if s.ID != id {
			continue
		}
		if s.MigrationName != "" {
			return fmt.Errorf("NATIVE_SMB_MIGRATION_RECOVERY_REQUIRED")
		}
		if s.GuestUpdate {
			return fmt.Errorf("NATIVE_SMB_GUEST_RECOVERY_REQUIRED")
		}
		fileID, err := smbRootFileIdentity(s.Path)
		if err != nil {
			return err
		}
		acls, err := loadSMBACLs()
		if err != nil {
			return err
		}
		identityVerified := false
		for _, root := range acls.Roots {
			if root.ID == id && strings.EqualFold(filepath.Clean(root.Path), filepath.Clean(s.Path)) && root.FileID == fileID {
				identityVerified = true
			}
		}
		volume, err := nativeSMBVolume(s.Path)
		if err != nil {
			return err
		}
		cat, err := ShareCatalog()
		if err != nil {
			return err
		}
		selectedIdentity := false
		for _, f := range cat.List() {
			selectedIdentity = selectedIdentity || f.ID == id && f.Available && strings.EqualFold(filepath.Clean(f.Path), filepath.Clean(s.Path)) && f.Identity == "win:"+fileID
		}
		if !verifiedSMBAccessRoot(volume.PersistentACL, selectedIdentity, identityVerified) {
			return fmt.Errorf("NATIVE_SMB_ACCESS_ROOT_CHANGED")
		}
		got, free, rc, err := getNativeShare(s.Name)
		if err != nil {
			return err
		}
		if rc != 0 {
			return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
		}
		owned := ownedNativeShare(s, got)
		free()
		if !owned {
			return fmt.Errorf("NATIVE_SMB_CHANGED_IN_WINDOWS: %s", s.Name)
		}
		// A prior interrupted save is recognized only at its two approved states.
		// Stage the next change from the actual descriptor, not an assumed side.
		if s.AccessUpdate {
			next := s
			next.AccountAccess, next.GuestAccess = s.NextAccountAccess, s.NextGuestAccess
			got, free, rc, err = getNativeShare(s.Name)
			if err != nil {
				return err
			}
			if rc != 0 {
				return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
			}
			sd, err := nativeShareSD(next)
			atTarget := err == nil && sameNativeSMBShareACL(got.SD, sd)
			free()
			if atTarget {
				s = next
			}
		}
		s.AccessUpdate, s.NextAccountAccess, s.NextGuestAccess = true, accountAccess, guestAccess
		c.Shares[i] = s
		if err = saveNativeSMB(c); err != nil {
			return err
		}
		target := s
		target.AccountAccess, target.GuestAccess = accountAccess, guestAccess
		target.AccessUpdate, target.NextAccountAccess, target.NextGuestAccess = false, "", ""
		if err = setNativeShareGuestACL(s, target); err != nil {
			return err
		}
		afterID, err := smbRootFileIdentity(s.Path)
		if err != nil {
			return err
		}
		if afterID != fileID {
			return fmt.Errorf("NATIVE_SMB_ACCESS_ROOT_CHANGED")
		}
		setting := nativeSMBAccessSetting{ID: id, Path: s.Path, FileID: fileID, Account: accountAccess, Guest: guestAccess}
		found := false
		for j, p := range c.Access {
			if p.ID == id {
				c.Access[j] = setting
				found = true
			}
		}
		if !found {
			if len(c.Access) >= 32 {
				return fmt.Errorf("NATIVE_SMB_ACCESS_LIMIT")
			}
			c.Access = append(c.Access, setting)
		}
		c.Shares[i] = target
		return saveNativeSMB(c)
	}
	cat, err := ShareCatalog()
	if err != nil {
		return err
	}
	for _, f := range cat.List() {
		if f.ID != id {
			continue
		}
		fileID, err := smbRootFileIdentity(f.Path)
		if err != nil {
			return err
		}
		if "win:"+fileID != f.Identity {
			return fmt.Errorf("NATIVE_SMB_ACCESS_ROOT_CHANGED")
		}
		setting := nativeSMBAccessSetting{ID: id, Path: f.Path, FileID: fileID, Account: accountAccess, Guest: guestAccess}
		for j, p := range c.Access {
			if p.ID == id {
				if p.FileID != fileID || !strings.EqualFold(p.Path, f.Path) {
					return fmt.Errorf("NATIVE_SMB_ACCESS_ROOT_CHANGED")
				}
				c.Access[j] = setting
				return saveNativeSMB(c)
			}
		}
		if len(c.Access) >= 32 {
			return fmt.Errorf("NATIVE_SMB_ACCESS_LIMIT")
		}
		c.Access = append(c.Access, setting)
		return saveNativeSMB(c)
	}
	return fmt.Errorf("NATIVE_SMB_SHARE_NOT_FOUND")
}

// Enumerate published disk shares in Windows, including shares not in the
// current catalog. External shares remain explicitly Windows-managed.
func enumerateNativeDiskShares() ([]nativeSMBShare, error) {
	proc := nativeNet.NewProc("NetShareEnum")
	if err := proc.Find(); err != nil {
		return nil, err
	}
	var resume uint32
	out := []nativeSMBShare{}
	for page := 0; page < 32; page++ {
		var buffer *nativeShare502
		var read, total uint32
		rc, _, _ := proc.Call(0, 502, uintptr(unsafe.Pointer(&buffer)), 64<<10, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if buffer != nil {
			if read > 1024 {
				nativeNet.NewProc("NetApiBufferFree").Call(uintptr(unsafe.Pointer(buffer)))
				return nil, fmt.Errorf("NATIVE_SMB_ENUM_LIMIT")
			}
			for _, v := range unsafe.Slice(buffer, int(read)) {
				name, path := windows.UTF16PtrToString(v.Name), windows.UTF16PtrToString(v.Path)
				if v.Type == 0 && name != "" && path != "" && name[len(name)-1] != '$' {
					out = append(out, nativeSMBShare{Name: name, Path: path})
				}
			}
			nativeNet.NewProc("NetApiBufferFree").Call(uintptr(unsafe.Pointer(buffer)))
		}
		runtime.KeepAlive(buffer)
		if rc == 0 {
			return out, nil
		}
		if rc != 234 {
			return nil, fmt.Errorf("NATIVE_SMB_ENUM_FAILED: %d", rc)
		}
	}
	return nil, fmt.Errorf("NATIVE_SMB_ENUM_LIMIT")
}

func SetNewNativeSMBAccess(path, account, guest string) error {
	if account == "" || guest == "" || !validSMBAccess(account) || !validSMBAccess(guest) {
		return fmt.Errorf("NATIVE_SMB_ACCESS_INVALID")
	}
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	cat, err := ShareCatalog()
	if err != nil {
		return err
	}
	nativeSMBMu.Lock()
	defer nativeSMBMu.Unlock()
	c, err := loadNativeSMB()
	if err != nil {
		return err
	}
	for _, f := range cat.List() {
		if !strings.EqualFold(filepath.Clean(f.Path), filepath.Clean(path)) {
			continue
		}
		for _, s := range c.Shares {
			if s.ID == f.ID {
				return fmt.Errorf("NATIVE_SMB_SHARE_ALREADY_PUBLISHED")
			}
		}
		if !f.Available || !strings.HasPrefix(f.Identity, "win:") {
			return fmt.Errorf("NATIVE_SMB_ACCESS_ROOT_UNAVAILABLE")
		}
		p := nativeSMBAccessSetting{ID: f.ID, Path: f.Path, FileID: strings.TrimPrefix(f.Identity, "win:"), Account: account, Guest: guest}
		for i, old := range c.Access {
			if old.ID == f.ID {
				c.Access[i] = p
				return saveNativeSMB(c)
			}
		}
		if len(c.Access) >= 32 {
			return fmt.Errorf("NATIVE_SMB_ACCESS_LIMIT")
		}
		c.Access = append(c.Access, p)
		return saveNativeSMB(c)
	}
	return fmt.Errorf("NATIVE_SMB_SHARE_NOT_FOUND")
}

func NativeSMBManagerFolders() ([]fileshare.Folder, error) {
	cat, err := ShareCatalog()
	if err != nil {
		return nil, err
	}
	rows := NativeSMBFolders(cat.List())
	nativeSMBMu.Lock()
	c, err := loadNativeSMB()
	nativeSMBMu.Unlock()
	for i, r := range rows {
		if !r.NativeShared {
			for _, p := range c.Access {
				if p.ID == r.ID {
					rows[i].AccountAccess, rows[i].GuestAccess = p.Account, p.Guest
				}
			}
		}
	}

	if err != nil {
		return rows, err
	}
	published, err := enumerateNativeDiskShares()
	if err != nil {
		return rows, err
	}
	for _, s := range published {
		found := false
		for _, receipt := range c.Shares {
			if receipt.MigrationName != "" && (strings.EqualFold(receipt.Name, s.Name) || strings.EqualFold(receipt.MigrationName, s.Name)) {
				found = true
				break
			}
		}
		for _, r := range rows {
			if strings.EqualFold(r.ShareName, s.Name) {
				found = true
				break
			}
		}
		if !found {
			rows = append(rows, fileshare.Folder{Name: s.Name, ShareName: s.Name, Path: s.Path, SMBURL: "smb://10.6.9.1/" + url.PathEscape(s.Name), Available: true, NativeShared: true, ExternalShare: true})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].ShareName) < strings.ToLower(rows[j].ShareName) })
	return rows, nil
}
