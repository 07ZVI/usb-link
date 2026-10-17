//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

type photoPolicyNativeStore struct{ dir string }

func (b *photoPolicyNativeStore) lock() (func(), error) {
	if !networkOnlyDriverStoreProtected(b.dir) {
		return nil, errors.New("PHOTO_POLICY_STORE_UNPROVEN")
	}
	sd, e := windows.SecurityDescriptorFromString(portablePropertyFileSDDL)
	if e != nil {
		return nil, e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Join(b.dir, "local-photo-policy.lock")), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, photoWindowsFailure("PHOTO_POLICY_STORE_BUSY", e)
	}
	var info windows.ByHandleFileInformation
	actual, se := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || se != nil || !groupingACLMatches(actual, sd) {
		windows.CloseHandle(h)
		return nil, errors.New("PHOTO_POLICY_LOCK_UNPROVEN")
	}
	return func() { windows.CloseHandle(h) }, nil
}
func (b *photoPolicyNativeStore) load() (photoPolicyJournal, error) {
	j := photoPolicyJournal{Schema: 1}
	if !networkOnlyDriverStoreProtected(b.dir) {
		return j, errors.New("PHOTO_POLICY_STORE_UNPROVEN")
	}
	data, e := readPortableProtectedFile(filepath.Join(b.dir, localPhotoPolicyJournalFile), localPhotoPolicyJournalLimit)
	if os.IsNotExist(e) {
		return j, nil
	}
	if e != nil {
		return j, photoWindowsFailure("PHOTO_POLICY_JOURNAL_UNREADABLE", e)
	}
	return decodePhotoPolicyJournal(data)
}
func (b *photoPolicyNativeStore) save(j photoPolicyJournal) error {
	if !j.valid() || !networkOnlyDriverStoreProtected(b.dir) {
		return errors.New("PHOTO_POLICY_STORE_UNPROVEN")
	}
	if _, e := b.load(); e != nil {
		return e
	}
	data, e := json.Marshal(j)
	if e != nil || len(data) > localPhotoPolicyJournalLimit {
		return errors.New("PHOTO_POLICY_JOURNAL_LIMIT")
	}
	f, temp, e := createPortableProtectedTemp(b.dir)
	if e != nil {
		return photoWindowsFailure("PHOTO_POLICY_JOURNAL_SAVE_FAILED", e)
	}
	defer os.Remove(temp)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return photoWindowsFailure("PHOTO_POLICY_JOURNAL_SAVE_FAILED", e)
	}
	if closeErr != nil {
		return closeErr
	}
	check, e := readPortableProtectedFile(temp, localPhotoPolicyJournalLimit)
	if e != nil || !bytes.Equal(check, data) {
		return errors.New("PHOTO_POLICY_JOURNAL_READBACK_FAILED")
	}
	if !networkOnlyDriverStoreProtected(b.dir) {
		return errors.New("PHOTO_POLICY_STORE_CHANGED")
	}
	path := filepath.Join(b.dir, localPhotoPolicyJournalFile)
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	check, e = readPortableProtectedFile(path, localPhotoPolicyJournalLimit)
	if e != nil || !bytes.Equal(check, data) {
		return errors.New("PHOTO_POLICY_JOURNAL_READBACK_FAILED")
	}
	_, e = decodePhotoPolicyJournal(check)
	return e
}

// Recovery is also compiled into public builds. It cannot add a deny entry.
func RestoreLocalPhotoPolicy(dir string) error {
	b := &photoPolicyNativeStore{dir: dir}
	unlock, e := b.lock()
	if e != nil {
		return e
	}
	defer unlock()
	return restorePhotoPolicy(b)
}
