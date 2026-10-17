//go:build windows && amd64

package exitrecord

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unsafe"
)

const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
const fileSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

var storeMu sync.Mutex

// Keep both directories open without delete sharing through the entire operation.
func holdDirectories(dir string) (func(), error) {
	if !runtimePattern.MatchString(filepath.Base(dir)) {
		return nil, ErrProtection
	}
	var handles []windows.Handle
	release := func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}
	for i, path := range []string{filepath.Dir(dir), dir} {
		p, e := windows.UTF16PtrFromString(path)
		if e != nil {
			release()
			return nil, ErrProtection
		}
		h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			release()
			return nil, ErrProtection
		}
		handles = append(handles, h)
		if !handleProtected(h, true, i == 0) {
			release()
			return nil, ErrProtection
		}
	}
	return release, nil
}
func handleProtected(h windows.Handle, dir, requireProtected bool) bool {
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
		if windows.GetAce(acl, i, &a) != nil || a == nil || (a.Header.AceSize != 20 && a.Header.AceSize != 24) || a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || a.Mask != fileAllAccess || a.Header.AceFlags & ^uint8(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.INHERITED_ACE) != 0 {
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
func readHeld(dir string) (Record, bool, error) {
	p, _ := windows.UTF16PtrFromString(recordPath(dir))
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return Record{}, false, nil
	}
	if e != nil {
		return Record{}, true, ErrRead
	}
	f := os.NewFile(uintptr(h), leaf)
	if f == nil {
		windows.CloseHandle(h)
		return Record{}, true, ErrRead
	}
	defer f.Close()
	if !handleProtected(h, false, true) {
		return Record{}, true, ErrProtection
	}
	b, e := io.ReadAll(io.LimitReader(f, Limit+1))
	if e != nil {
		return Record{}, true, ErrRead
	}
	r, e := Decode(b)
	return r, true, e
}
func Read(dir string) (Record, bool, error) {
	storeMu.Lock()
	defer storeMu.Unlock()
	// An absent record is ordinary before the first exit; never follow a leaf link.
	if _, e := os.Lstat(recordPath(dir)); os.IsNotExist(e) {
		return Record{}, false, nil
	}
	release, e := holdDirectories(dir)
	if e != nil {
		return Record{}, true, e
	}
	defer release()
	return readHeld(dir)
}
func Write(dir string, r Record) error {
	b, e := Encode(r)
	if e != nil {
		return e
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	release, e := holdDirectories(dir)
	if e != nil {
		return e
	}
	defer release()
	if _, _, e = readHeld(dir); e != nil {
		return e
	}
	var nonce [12]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return ErrWrite
	}
	tmp := filepath.Join(filepath.Dir(dir), "exit-record-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(tmp)
	tp, _ := windows.UTF16PtrFromString(tmp)
	dst, _ := windows.UTF16PtrFromString(recordPath(dir))
	sd, e := windows.SecurityDescriptorFromString(fileSDDL)
	if e != nil {
		return ErrProtection
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return ErrWrite
	}
	f := os.NewFile(uintptr(h), leaf)
	if f == nil {
		windows.CloseHandle(h)
		return ErrWrite
	}
	if !handleProtected(h, false, true) {
		f.Close()
		return ErrProtection
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	if e == nil {
		_, e = f.Seek(0, io.SeekStart)
	}
	if e == nil {
		var got []byte
		got, e = io.ReadAll(io.LimitReader(f, Limit+1))
		if e == nil && !bytes.Equal(got, b) {
			e = ErrWrite
		}
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrWrite
	}
	if windows.MoveFileEx(tp, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH) != nil {
		return ErrWrite
	}
	got, found, e := readHeld(dir)
	if e != nil || !found {
		return ErrWrite
	}
	gb, e := Encode(got)
	if e != nil || !bytes.Equal(gb, b) {
		return ErrWrite
	}
	return nil
}
