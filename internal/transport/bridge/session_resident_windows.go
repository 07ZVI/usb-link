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
	"unsafe"
)

// Resident journals retain the same BA/SY-only protected, real one-link leaf
// and atomic readback rules as retained journals, with a separate strict schema.
func ReadResidentOwnedSession(dir string) (OwnedSession, error) {
	var zero OwnedSession
	if !retainedRuntimeProtected(dir) {
		return zero, errors.New("MAC_RESIDENT_RUNTIME_UNPROVEN")
	}
	p, _ := windows.UTF16PtrFromString(filepath.Join(dir, "owned-session.json"))
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return zero, errors.New("MAC_RESIDENT_RECORD_UNREADABLE")
	}
	f := os.NewFile(uintptr(h), "owned-session.json")
	if f == nil {
		windows.CloseHandle(h)
		return zero, errors.New("MAC_RESIDENT_RECORD_UNREADABLE")
	}
	defer f.Close()
	if !retainedHandleProtected(h, false, true) {
		return zero, errors.New("MAC_RESIDENT_RECORD_PROTECTION_UNPROVEN")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return zero, errors.New("MAC_RESIDENT_RECORD_UNREADABLE")
	}
	return ParseResidentSession(b)
}
func WriteResidentOwnedSession(dir string, v OwnedSession) error {
	if ValidateResidentSession(v) != nil || !retainedRuntimeProtected(dir) {
		return errors.New("MAC_RESIDENT_RECORD_PLAN_UNPROVEN")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e = ParseResidentSession(b); e != nil {
		return e
	}
	// Existing fixed leaf must be regular, one-link and not a reparse target even
	// on first promotion; a protected retained leaf is reread after replacement.
	dst := filepath.Join(dir, "owned-session.json")
	p, _ := windows.UTF16PtrFromString(dst)
	old, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil && e != windows.ERROR_FILE_NOT_FOUND {
		return errors.New("MAC_RESIDENT_RECORD_UNREADABLE")
	}
	if e == nil {
		var info windows.ByHandleFileInformation
		e = windows.GetFileInformationByHandle(old, &info)
		ownedLeaf := retainedHandleProtected(old, false, false)
		windows.CloseHandle(old)
		if e != nil || !ownedLeaf || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
			return errors.New("MAC_RESIDENT_RECORD_PROTECTION_UNPROVEN")
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
		return errors.New("MAC_RESIDENT_RECORD_CREATE_FAILED")
	}
	f := os.NewFile(uintptr(h), "owned-session.json")
	if f == nil {
		windows.CloseHandle(h)
		return errors.New("MAC_RESIDENT_RECORD_CREATE_FAILED")
	}
	if !retainedHandleProtected(h, false, true) {
		f.Close()
		return errors.New("MAC_RESIDENT_RECORD_PROTECTION_UNPROVEN")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("MAC_RESIDENT_RECORD_WRITE_FAILED")
	}
	if !retainedRuntimeProtected(dir) || windows.MoveFileEx(tp, p, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH) != nil {
		return errors.New("MAC_RESIDENT_RECORD_COMMIT_FAILED")
	}
	got, e := ReadResidentOwnedSession(dir)
	if e != nil || got != v {
		return errors.New("MAC_RESIDENT_RECORD_READBACK_FAILED")
	}
	return nil
}

// ConsumeResidentOwnedSession removes the exact protected journal by its held
// handle, only after the caller proves complete adapter absence under the
// runtime ownership lock. It never grants firewall or adapter removal rights.
func ConsumeResidentOwnedSession(dir string, expected OwnedSession, verifyAbsence func() error) error {
	if ValidateResidentSession(expected) != nil || verifyAbsence == nil || !retainedRuntimeProtected(dir) {
		return errors.New("MAC_RESIDENT_CONSUME_PLAN_UNPROVEN")
	}
	p := windows.StringToUTF16Ptr(filepath.Join(dir, "owned-session.json"))
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.DELETE, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return errors.New("MAC_RESIDENT_RECORD_UNREADABLE")
	}
	f := os.NewFile(uintptr(h), "owned-session.json")
	if f == nil {
		windows.CloseHandle(h)
		return errors.New("MAC_RESIDENT_RECORD_UNREADABLE")
	}
	defer f.Close()
	if !retainedHandleProtected(h, false, true) {
		return errors.New("MAC_RESIDENT_RECORD_PROTECTION_UNPROVEN")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return errors.New("MAC_RESIDENT_RECORD_UNREADABLE")
	}
	current, e := ParseResidentSession(b)
	if e != nil || current != expected {
		return errors.New("MAC_RESIDENT_RECORD_CHANGED")
	}
	if e = verifyAbsence(); e != nil {
		return e
	}
	if !retainedRuntimeProtected(dir) || !retainedHandleProtected(h, false, true) {
		return errors.New("MAC_RESIDENT_RECORD_PROTECTION_UNPROVEN")
	}
	remove := byte(1)
	if e = windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &remove, 1); e != nil {
		return errors.New("MAC_RESIDENT_RECORD_CONSUME_FAILED")
	}
	return f.Close()
}
