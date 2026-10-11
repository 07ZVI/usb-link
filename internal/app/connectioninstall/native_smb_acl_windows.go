//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"suhang/usbnet/internal/sharing/fileshare"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Backup only root DACLs changed for our dedicated/Guest identity. Restoring
// requires an exact readback of the last applied DACL, so external ACL edits
// are never silently overwritten. Owners, SACLs and unrelated ACEs are retained.
type smbACLReceipt struct {
	ID, Path, Before, After, FileID string
	PreviousAfter                   string
	AcceptedBaseline                bool
	Retained                        bool
	Grants                          []string
}
type smbACLConfiguration struct{ Roots []smbACLReceipt }

func smbACLPath() (string, error) {
	d, e := SecurityDirectory()
	return filepath.Join(d, "native-smb-acls.json"), e
}
func loadSMBACLs() (smbACLConfiguration, error) {
	var c smbACLConfiguration
	p, e := smbACLPath()
	if e != nil {
		return c, e
	}
	if e = readNativeSMBState(p, &c); os.IsNotExist(e) {
		return c, nil
	} else if e != nil {
		return c, e
	}
	if len(c.Roots) > 32 {
		return c, fmt.Errorf("SMB_ACL_RECEIPT_LIMIT")
	}
	seen := map[string]bool{}
	for _, r := range c.Roots {
		if !fileshare.ValidFolderID(r.ID) || !filepath.IsAbs(r.Path) || len(r.Path) > 4096 || r.Before == "" || seen[r.ID] || r.Retained && (!r.AcceptedBaseline || r.ID != "000000000000000000000001") || r.AcceptedBaseline && (r.ID != "000000000000000000000001" || r.FileID == "") {
			return c, fmt.Errorf("SMB_ACL_RECEIPT_INVALID")
		}
		if _, e := windows.SecurityDescriptorFromString(r.Before); e != nil {
			return c, e
		}
		if r.PreviousAfter != "" {
			if _, e := windows.SecurityDescriptorFromString(r.PreviousAfter); e != nil {
				return c, e
			}
		}
		if r.After != "" {
			if _, e := windows.SecurityDescriptorFromString(r.After); e != nil {
				return c, e
			}
		}
		if r.FileID != "" {
			if len(r.FileID) != 25 || r.FileID[8] != ':' {
				return c, fmt.Errorf("SMB_ACL_IDENTITY_INVALID")
			}
			if _, e := hex.DecodeString(strings.ReplaceAll(r.FileID, ":", "")); e != nil {
				return c, e
			}
		}
		seenGrants := map[string]bool{}
		for _, sid := range r.Grants {
			if seenGrants[sid] {
				return c, fmt.Errorf("SMB_ACL_GRANTS_INVALID")
			}
			seenGrants[sid] = true
			if _, e := windows.StringToSid(sid); e != nil {
				return c, e
			}
		}
		if len(r.Grants) > 2 {
			return c, fmt.Errorf("SMB_ACL_GRANTS_INVALID")
		}
		seen[r.ID] = true
	}
	return c, nil
}

// Bind new journals to a directory identity, not just a drive letter/path.
func writeSMBACLs(path string, c smbACLConfiguration) error {
	data, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if len(data)+1024 > 1<<20 {
		return fmt.Errorf("SMB_ACL_JOURNAL_TOO_LARGE")
	}
	return writeRemote(path, c)
}

func smbRootSecurity(path string) (*windows.SECURITY_DESCRIPTOR, string, error) {
	for n := filepath.Clean(path); ; n = filepath.Dir(n) {
		if e := noReparse(n); e != nil {
			return nil, "", e
		}
		if filepath.Dir(n) == n {
			break
		}
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, "", e
	}
	h, e := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, "", e
	}
	defer windows.CloseHandle(h)
	var attrs windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &attrs); e != nil {
		return nil, "", e
	}
	if attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return nil, "", fmt.Errorf("SMB_ROOT_IDENTITY_INVALID")
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	return sd, smbRootFileID(attrs), e
}

// Directory identity is independent of whether the filesystem supports DACLs.
func smbRootFileIdentity(path string) (string, error) {
	for n := filepath.Clean(path); ; n = filepath.Dir(n) {
		if e := noReparse(n); e != nil {
			return "", e
		}
		if filepath.Dir(n) == n {
			break
		}
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return "", e
	}
	h, e := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return "", e
	}
	defer windows.CloseHandle(h)
	var attrs windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &attrs); e != nil {
		return "", e
	}
	if attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return "", fmt.Errorf("SMB_ROOT_IDENTITY_INVALID")
	}
	return smbRootFileID(attrs), nil
}

func smbRootFileID(a windows.ByHandleFileInformation) string {
	return fmt.Sprintf("%08x:%08x%08x", a.VolumeSerialNumber, a.FileIndexHigh, a.FileIndexLow)
}

// Windows can update the auto-inheritance control flags while applying a DACL.
// Compare the protection bit and every ACE, without relaxing any access entry.
func sameSMBRootDACL(a, b string) bool {
	as, e := windows.SecurityDescriptorFromString(a)
	if e != nil {
		return false
	}
	bs, e := windows.SecurityDescriptorFromString(b)
	if e != nil {
		return false
	}
	ac, _, e := as.Control()
	if e != nil {
		return false
	}
	bc, _, e := bs.Control()
	if e != nil {
		return false
	}
	if ac&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) != bc&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) {
		return false
	}
	aa, _, ae := as.DACL()
	ba, _, be := bs.DACL()
	if ae != nil || be != nil {
		return a == b
	}
	if aa == nil || ba == nil {
		return aa == nil && ba == nil
	}
	if aa.AceCount != ba.AceCount {
		return false
	}
	for i := uint32(0); i < uint32(aa.AceCount); i++ {
		var av, bv *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(aa, i, &av) != nil || windows.GetAce(ba, i, &bv) != nil || av == nil || bv == nil || av.Header.AceSize < 4 || av.Header.AceSize != bv.Header.AceSize {
			return false
		}
		if !bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(av)), int(av.Header.AceSize)), unsafe.Slice((*byte)(unsafe.Pointer(bv)), int(bv.Header.AceSize))) {
			return false
		}
	}
	return true
}
func grantSMBRoot(id, path string, sids []string) error {
	return updateSMBRootGrants(id, path, sids, false)
}
func updateSMBRootGrants(id, path string, sids []string, reconfigure bool) error {
	if len(sids) == 0 && !reconfigure {
		return nil
	}
	c, e := loadSMBACLs()
	if e != nil {
		return e
	}
	p, e := smbACLPath()
	if e != nil {
		return e
	}
	volume, e := nativeSMBVolume(path)
	if e != nil {
		return fmt.Errorf("SMB_FOLDER_VOLUME_UNAVAILABLE (%s): %w", path, e)
	}
	var previous *smbACLReceipt
	for _, r := range c.Roots {
		if r.ID == id {
			copy := r
			previous = &copy
			continue
		}
		a, b := strings.ToLower(filepath.Clean(r.Path))+`\`, strings.ToLower(filepath.Clean(path))+`\`
		if strings.HasPrefix(a, b) || strings.HasPrefix(b, a) {
			return fmt.Errorf("SMB_SELECTED_FOLDERS_OVERLAP")
		}
	}
	if !volume.PersistentACL {
		if previous != nil {
			return fmt.Errorf("SMB_FOLDER_FILESYSTEM_CHANGED: %s", path)
		}
		// FAT/exFAT have no persistent filesystem ACL. The independent SMB share
		// DACL still restricts network access to the selected identity/Guest.
		return nil
	}
	sd, fileID, e := smbRootSecurity(path)
	if e != nil {
		return fmt.Errorf("SMB_FOLDER_DACL_READ_FAILED (%s): %w", path, e)
	}
	before := sd.String()
	current := before
	acceptedBaseline := previous != nil && previous.AcceptedBaseline
	if previous != nil {
		if !strings.EqualFold(previous.Path, path) || previous.FileID != "" && previous.FileID != fileID {
			return fmt.Errorf("SMB_ROOT_IDENTITY_CHANGED: %s", path)
		}
		if !previous.Retained && previous.After != "" && sameSMBRootDACL(before, previous.After) && (!reconfigure || sameSMBGrants(previous.Grants, sids)) {
			return nil
		}
		if sameSMBRootDACL(before, previous.Before) {
			if previous.Retained {
				for i, r := range c.Roots {
					if r.ID == id {
						c.Roots = append(c.Roots[:i], c.Roots[i+1:]...)
						break
					}
				}
				previous = nil
			} else {
				if e := restoreSMBRoot(id); e != nil {
					return e
				}
				return updateSMBRootGrants(id, path, sids, reconfigure)
			}
		}
		if previous != nil {
			if previous.After == "" || !sameSMBRootDACL(before, previous.After) && !sameSMBRootDACL(before, previous.PreviousAfter) {
				return fmt.Errorf("SMB_FOLDER_ACL_CHANGED: %s", path)
			}
			if sameSMBRootDACL(before, previous.After) && (!reconfigure || sameSMBGrants(previous.Grants, sids)) {
				return nil
			}
			before = previous.Before
			sd, e = windows.SecurityDescriptorFromString(before)
			if e != nil {
				return e
			}
			for i, r := range c.Roots {
				if r.ID == id {
					c.Roots = append(c.Roots[:i], c.Roots[i+1:]...)
					break
				}
			}
		}
	}

	acl, _, e := sd.DACL()
	control, _, ce := sd.Control()
	if ce != nil {
		return ce
	}
	absent := control&windows.SE_DACL_PRESENT == 0
	if e != nil && !(e == windows.ERROR_OBJECT_NOT_FOUND && absent) {
		return fmt.Errorf("SMB_FOLDER_DACL_UNAVAILABLE (%s): %w", path, e)
	}
	// Preserve an already permissive NULL/absent DACL. An allocated empty ACL
	// is different: it denies access and must proceed through the owned grant.
	if smbDACLMode(volume.PersistentACL, !absent, acl == nil) == "already-permissive" {
		return nil
	}
	entries := []windows.EXPLICIT_ACCESS{}
	var pinned runtime.Pinner
	defer pinned.Unpin()
	for _, text := range sids {
		sid, e := windows.StringToSid(text)
		if e != nil {
			return e
		}
		pinned.Pin(sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{AccessPermissions: 0x1301bf, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)}})
	}
	merged, e := windows.ACLFromEntries(entries, acl)
	if e != nil {
		return e
	}
	// Persist both sides before the potentially long inheritable ACL update.
	// A crash between SetSecurityInfo and readback still has a recoverable plan.
	planned, e := sd.ToAbsolute()
	if e != nil {
		return e
	}
	if e = planned.SetDACL(merged, true, false); e != nil {
		return e
	}
	relative, e := planned.ToSelfRelative()
	if e != nil {
		return e
	}
	c.Roots = append(c.Roots, smbACLReceipt{ID: id, Path: path, Before: before, After: relative.String(), FileID: fileID, AcceptedBaseline: acceptedBaseline, Grants: append([]string(nil), sids...), PreviousAfter: current})
	if e = writeSMBACLs(p, c); e != nil {
		return e
	}
	after := current
	if !sameSMBRootDACL(current, relative.String()) {
		after, e = setSMBRootDACL(id, path, fileID, current, restoreSMBDACLInfo(sd), merged)
	}

	if e != nil {
		return e
	}
	c.Roots[len(c.Roots)-1].After = after
	c.Roots[len(c.Roots)-1].PreviousAfter = ""
	if e = writeSMBACLs(p, c); e != nil {
		// The staged receipt remains durable. Roll back to the previous owned
		// DACL, preserving dedicated-account access during a failed Guest change.
		original, er := windows.SecurityDescriptorFromString(current)
		if er == nil {
			acl, _, er := original.DACL()
			if er == nil {
				_, er = setSMBRootDACL(id, path, fileID, after, restoreSMBDACLInfo(original), acl)
			}
			if er != nil {
				return fmt.Errorf("%w; SMB_ACL_ROLLBACK_UNCONFIRMED: %v", e, er)
			}
		} else {
			return fmt.Errorf("%w; SMB_ACL_ROLLBACK_UNCONFIRMED: %v", e, er)
		}
		return e
	}
	return nil
}
func restoreSMBRoot(id string) error {
	c, e := loadSMBACLs()
	if e != nil {
		return e
	}
	p, e := smbACLPath()
	if e != nil {
		return e
	}
	for i, r := range c.Roots {
		if r.ID != id {
			continue
		}
		if r.Retained {
			return nil
		}
		if !filepath.IsAbs(r.Path) || r.Before == "" {
			return fmt.Errorf("SMB_ACL_RESTORE_UNCONFIRMED")
		}
		currentSD, fileID, e := smbRootSecurity(r.Path)
		if e != nil {
			return e
		}
		if r.FileID != "" && fileID != r.FileID {
			return fmt.Errorf("SMB_ROOT_IDENTITY_CHANGED: %s", r.Path)
		}
		current := currentSD.String()
		if sameSMBRootDACL(current, r.Before) {
			c = completedSMBACLRestore(c, i)
			return writeSMBACLs(p, c)
		}
		if r.After == "" {
			return fmt.Errorf("SMB_ACL_RESTORE_UNCONFIRMED")
		}
		if !sameSMBRootDACL(current, r.After) && !sameSMBRootDACL(current, r.PreviousAfter) {
			return fmt.Errorf("SMB_FOLDER_ACL_CHANGED: %s", r.Path)
		}
		sd, e := windows.SecurityDescriptorFromString(r.Before)
		if e != nil {
			return e
		}
		acl, _, e := sd.DACL()
		if e != nil {
			return e
		}
		control, _, e := sd.Control()
		if e != nil {
			return e
		}
		info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
		if control&windows.SE_DACL_PROTECTED != 0 {
			info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
		}
		if _, e = setSMBRootDACL(id, r.Path, r.FileID, current, info, acl); e != nil {
			return e
		}
		c = completedSMBACLRestore(c, i)
		return writeSMBACLs(p, c)
	}
	return nil
}

func completedSMBACLRestore(c smbACLConfiguration, i int) smbACLConfiguration {
	if c.Roots[i].AcceptedBaseline {
		c.Roots[i].After = c.Roots[i].Before
		c.Roots[i].Retained = true
		c.Roots[i].PreviousAfter = ""
		c.Roots[i].Grants = nil
	} else {
		c.Roots = append(c.Roots[:i], c.Roots[i+1:]...)
	}
	return c
}

func restoreSMBDACLInfo(sd *windows.SECURITY_DESCRIPTOR) windows.SECURITY_INFORMATION {
	c, _, _ := sd.Control()
	if c&windows.SE_DACL_PROTECTED != 0 {
		return windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION
}

// Verify ABI assumptions used by Windows ACL and native share calls at compile time.
var _ [72 - int(unsafe.Sizeof(nativeShare502{}))]byte
var _ [int(unsafe.Sizeof(nativeShare502{})) - 72]byte

func setSMBRootDACL(id, path, fileID, expected string, info windows.SECURITY_INFORMATION, acl *windows.ACL) (after string, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	stage, administrator := "validate-journal", ""
	defer func() {
		recordSMBACLWrite(id, stage, administrator, err)
		if err != nil {
			err = fmt.Errorf("資料夾權限保存失敗（%s）：%w", smbACLStageLabel(stage), err)
		}
	}()
	// A selected, identity-bound recovery record is required before an
	// administrative write. No arbitrary pathname, owner or SACL mutation.
	journal, e := loadSMBACLs()
	if e != nil {
		return "", e
	}
	approved := false
	for _, r := range journal.Roots {
		if r.ID == id && fileID != "" && r.FileID == fileID && strings.EqualFold(filepath.Clean(r.Path), filepath.Clean(path)) &&
			(sameSMBRootDACL(expected, r.Before) || sameSMBRootDACL(expected, r.After) || r.PreviousAfter != "" && sameSMBRootDACL(expected, r.PreviousAfter)) {
			approved = true
		}
	}
	if !approved {
		return "", fmt.Errorf("SMB_ACL_SELECTED_ROOT_UNPROVEN")
	}
	var pin windows.Handle
	var desktop shareIdentity
	stage = "open-selected-root"
	open := func() error {
		for n := filepath.Clean(path); ; n = filepath.Dir(n) {
			if e := noReparse(n); e != nil {
				return e
			}
			if filepath.Dir(n) == n {
				break
			}
		}
		p, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return e
		}
		pin, e = windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			return e
		}
		if id != "000000000000000000000001" {
			var token windows.Token
			if e = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); e != nil {
				return e
			}
			defer token.Close()
			desktop, e = shareTokenIdentity(token)
			if e != nil {
				return e
			}
		}
		return verifySMBACLHandle(pin, fileID, expected)
	}
	if id == "000000000000000000000001" {
		root, e := dataRoot("Shared Files")
		if e != nil {
			return "", e
		}
		if !strings.EqualFold(filepath.Clean(path), filepath.Join(root, "Shared Files")) {
			return "", fmt.Errorf("SMB_DEFAULT_ROOT_CHANGED")
		}
		err = open()
		administrator = "protected-default-root"
	} else {
		user, release, e := shareUser()
		if e != nil {
			return "", e
		}
		defer release()
		// Readability, no-redirection checks and the pinned original handle are
		// established as the same ordinary user used by the catalog.
		err = user(open)
	}
	if pin != 0 && pin != windows.InvalidHandle {
		defer windows.CloseHandle(pin)
	}
	if err != nil {
		return "", err
	}
	stage = "validate-administrator"
	if id != "000000000000000000000001" {
		operator, e := shareTokenIdentity(windows.GetCurrentProcessToken())
		if e != nil {
			return "", e
		}
		bound, _ := BoundCoreOwnerSID()
		if e = validateSMBACLAdministrator(operator, desktop, bound); e != nil {
			return "", e
		}
		administrator = "same-owner-admin"
		if operator.SID == "S-1-5-18" {
			administrator = "bound-core-service"
		}
	}
	// Reopen the already approved directory rather than resolving a pathname
	// with administrative authority. ReOpenFile rejects directory handles.
	stage = "open-permission-handle"
	var thread windows.Token
	if e = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &thread); e == nil {
		thread.Close()
		return "", fmt.Errorf("SMB_ACL_IMPERSONATION_ACTIVE")
	} else if e != windows.ERROR_NO_TOKEN {
		return "", e
	}
	h, e := reopenSMBDirectory(pin, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES)
	if e != nil {
		return "", e
	}
	defer windows.CloseHandle(h)
	stage = "verify-permission-handle"
	if e = verifySMBACLHandle(h, fileID, expected); e != nil {
		return "", e
	}
	stage = "apply-folder-permissions"
	if e = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil); e != nil {
		return "", e
	}
	stage = "read-back-folder-permissions"
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return "", e
	}
	after = sd.String()
	stage = "verify-applied-permissions"
	wanted, e := windows.SecurityDescriptorFromString(expected)
	if e != nil {
		return "", e
	}
	abs, e := wanted.ToAbsolute()
	if e != nil {
		return "", e
	}
	if e = abs.SetDACL(acl, true, false); e != nil {
		return "", e
	}
	protection := windows.SECURITY_DESCRIPTOR_CONTROL(0)
	if info&windows.PROTECTED_DACL_SECURITY_INFORMATION != 0 {
		protection = windows.SE_DACL_PROTECTED
	}
	if e = abs.SetControl(windows.SE_DACL_PROTECTED, protection); e != nil {
		return "", e
	}
	result, e := abs.ToSelfRelative()
	if e != nil {
		return "", e
	}
	if !sameSMBRootDACL(after, result.String()) {
		return "", fmt.Errorf("SMB_FOLDER_PERMISSION_READBACK_CHANGED")
	}
	stage = "complete"
	return after, nil
}

func verifySMBACLHandle(h windows.Handle, fileID, expected string) error {
	var attrs windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &attrs); e != nil {
		return e
	}
	if attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("SMB_ROOT_IDENTITY_INVALID")
	}
	if smbRootFileID(attrs) != fileID {
		return fmt.Errorf("SMB_ROOT_IDENTITY_CHANGED")
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	if sd.String() != expected {
		return fmt.Errorf("SMB_ROOT_ACL_CHANGED_DURING_SETUP")
	}
	return nil
}

func ownedSMBDefaultDACL(path string, actual, expected *windows.SECURITY_DESCRIPTOR) bool {
	c, e := loadSMBACLs()
	if e != nil || actual == nil || expected == nil {
		return false
	}
	for _, r := range c.Roots {
		if r.ID == "000000000000000000000001" && strings.EqualFold(r.Path, path) && (r.AcceptedBaseline || sameSMBRootDACL(r.Before, expected.String())) && (sameSMBRootDACL(r.After, actual.String()) || sameSMBRootDACL(r.PreviousAfter, actual.String())) {
			if r.FileID != "" {
				_, fileID, err := smbRootSecurity(path)
				if err != nil || fileID != r.FileID {
					return false
				}
			}
			return true
		}
	}
	return false
}

type nativeSMBVolumeInfo struct {
	Filesystem    string `json:"filesystem"`
	PersistentACL bool   `json:"persistent_acl"`
}

func nativeSMBVolume(path string) (nativeSMBVolumeInfo, error) {
	var info nativeSMBVolumeInfo
	text, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return info, e
	}
	root := make([]uint16, 32768)
	if e = windows.GetVolumePathName(text, &root[0], uint32(len(root))); e != nil {
		return info, e
	}
	var flags uint32
	name := make([]uint16, 256)
	if e = windows.GetVolumeInformation(&root[0], nil, 0, nil, nil, &flags, &name[0], uint32(len(name))); e != nil {
		return info, e
	}
	info.Filesystem = windows.UTF16ToString(name)
	info.PersistentACL = flags&windows.FILE_PERSISTENT_ACLS != 0
	return info, nil
}

// Read only selected catalog roots; no raw DACLs, account secrets or arbitrary paths.
func NativeSMBFolderDiagnostics() []map[string]any {
	c, e := ShareCatalog()
	if e != nil {
		return []map[string]any{{"problem": e.Error()}}
	}
	rows := []map[string]any{}
	for _, f := range NativeSMBFolders(c.List()) {
		row := map[string]any{"id": f.ID, "name": f.Name, "shared": f.NativeShared}
		v, e := nativeSMBVolume(f.Path)
		if e != nil {
			row["problem"] = e.Error()
		} else {
			row["filesystem"] = v.Filesystem
			row["persistent_acl"] = v.PersistentACL
			if !v.PersistentACL {
				row["dacl"] = "filesystem-no-acl"
			} else {
				sd, e := windows.GetNamedSecurityInfo(f.Path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
				if e != nil {
					row["problem"] = e.Error()
				} else {
					acl, _, e := sd.DACL()
					ctl, _, ce := sd.Control()
					present := ctl&windows.SE_DACL_PRESENT != 0
					if ce != nil || e != nil && !(e == windows.ERROR_OBJECT_NOT_FOUND && !present) {
						row["dacl"] = "unavailable"
					} else {
						row["dacl"] = smbDACLMode(true, present, acl == nil)
						if acl != nil {
							row["ace_count"] = acl.AceCount
						}
					}
				}
			}
		}
		rows = append(rows, row)
	}
	return rows
}
