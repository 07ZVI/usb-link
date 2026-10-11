//go:build windows && amd64

package bridge

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"unsafe"
)

const retainedFileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
const retainedRecordSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

var ownedRuntimeName = regexp.MustCompile(`^mac-runtime-([a-f0-9]{64}|[0-9]+\.[0-9]+\.[0-9]+)$`)

// Every retained record is a protected fixed leaf; a legacy unprotected record
// is never imported as a retained lease. Neither record nor runtime name grants
// native ownership by itself.
func retainedRuntimeProtected(dir string) bool {
	if !ownedRuntimeName.MatchString(filepath.Base(dir)) {
		return false
	}
	for i, p := range []string{filepath.Dir(dir), dir} {
		path, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return false
		}
		h, e := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			return false
		}
		ok := retainedHandleProtected(h, true, i == 0)
		windows.CloseHandle(h)
		if !ok {
			return false
		}
	}
	return true
}
func retainedHandleProtected(h windows.Handle, dir, requireProtected bool) bool {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!dir && info.NumberOfLinks != 1) || ((info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != dir) {
		return false
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return false
	}
	owner, _, e := sd.Owner()
	ba, be := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	sy, se := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if e != nil || be != nil || se != nil || owner == nil || (!owner.Equals(ba) && !owner.Equals(sy)) {
		return false
	}
	ctl, _, e := sd.Control()
	if e != nil || (requireProtected && ctl&windows.SE_DACL_PROTECTED == 0) {
		return false
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 2 {
		return false
	}
	seen := map[string]bool{}
	for i := uint32(0); i < 2; i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil || a == nil || (a.Header.AceSize != 20 && a.Header.AceSize != 24) || a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || a.Mask != retainedFileAllAccess || a.Header.AceFlags & ^uint8(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.INHERITED_ACE) != 0 {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		if !sid.Equals(ba) && !sid.Equals(sy) {
			return false
		}
		s := sid.String()
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return len(seen) == 2
}
func ReadRetainedOwnedSession(dir string) (OwnedSession, error) {
	var zero OwnedSession
	if !retainedRuntimeProtected(dir) {
		return zero, errors.New("MAC_RETAINED_RUNTIME_UNPROVEN")
	}
	p, _ := windows.UTF16PtrFromString(filepath.Join(dir, "owned-session.json"))
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return zero, errors.New("MAC_RETAINED_RECORD_UNREADABLE")
	}
	f := os.NewFile(uintptr(h), "owned-session.json")
	if f == nil {
		windows.CloseHandle(h)
		return zero, errors.New("MAC_RETAINED_RECORD_UNREADABLE")
	}
	defer f.Close()
	if !retainedHandleProtected(h, false, true) {
		return zero, errors.New("MAC_RETAINED_RECORD_PROTECTION_UNPROVEN")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return zero, errors.New("MAC_RETAINED_RECORD_UNREADABLE")
	}
	return ParseRetainedSession(b)
}
func WriteRetainedOwnedSession(dir string, v OwnedSession) error {
	if ValidateRetainedSession(v) != nil || !retainedRuntimeProtected(dir) {
		return errors.New("MAC_RETAINED_RECORD_PLAN_UNPROVEN")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e = ParseRetainedSession(b); e != nil {
		return e
	}
	// Existing fixed leaf must be regular, one-link and not a reparse target even
	// on first promotion; a protected retained leaf is reread after replacement.
	dst := filepath.Join(dir, "owned-session.json")
	p, _ := windows.UTF16PtrFromString(dst)
	old, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil && e != windows.ERROR_FILE_NOT_FOUND {
		return errors.New("MAC_RETAINED_RECORD_UNREADABLE")
	}
	if e == nil {
		var info windows.ByHandleFileInformation
		e = windows.GetFileInformationByHandle(old, &info)
		windows.CloseHandle(old)
		if e != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
			return errors.New("MAC_RETAINED_RECORD_PROTECTION_UNPROVEN")
		}
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	tmp := filepath.Join(dir, "owned-session-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(tmp)
	tp, _ := windows.UTF16PtrFromString(tmp)
	sd, e := windows.SecurityDescriptorFromString(retainedRecordSDDL)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return errors.New("MAC_RETAINED_RECORD_CREATE_FAILED")
	}
	f := os.NewFile(uintptr(h), "owned-session.json")
	if f == nil {
		windows.CloseHandle(h)
		return errors.New("MAC_RETAINED_RECORD_CREATE_FAILED")
	}
	if !retainedHandleProtected(h, false, true) {
		f.Close()
		return errors.New("MAC_RETAINED_RECORD_PROTECTION_UNPROVEN")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("MAC_RETAINED_RECORD_WRITE_FAILED")
	}
	if !retainedRuntimeProtected(dir) || windows.MoveFileEx(tp, p, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH) != nil {
		return errors.New("MAC_RETAINED_RECORD_COMMIT_FAILED")
	}
	got, e := ReadRetainedOwnedSession(dir)
	if e != nil || got != v && (got.Version != v.Version || got.GUID != v.GUID || got.Token != v.Token || got.Status != v.Status || got.Retained == nil || *got.Retained != *v.Retained) {
		return errors.New("MAC_RETAINED_RECORD_READBACK_FAILED")
	}
	return nil
}
