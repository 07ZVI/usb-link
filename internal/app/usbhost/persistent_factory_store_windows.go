//go:build windows && amd64

package usbhost

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

const persistentFactoryFile = "usb-host-persistent-factory.json"

func readFactoryProtected(dir, name string, limit int64) ([]byte, bool, error) {
	if !removalDirectoryProtected(dir) {
		return nil, false, errors.New("USB_HOST_FACTORY_DIRECTORY_UNPROVEN")
	}
	path := filepath.Join(dir, name)
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, false, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return nil, false, nil
	}
	if e != nil {
		return nil, false, errors.New("USB_HOST_FACTORY_RECORD_UNREADABLE")
	}
	var info windows.ByHandleFileInformation
	sd, se := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if se != nil || !recreateJournalACLMatches(sd) || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		windows.CloseHandle(h)
		return nil, false, errors.New("USB_HOST_FACTORY_RECORD_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, false, errors.New("USB_HOST_FACTORY_RECORD_UNREADABLE")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, true, errors.New("USB_HOST_FACTORY_RECORD_UNREADABLE")
	}
	return b, true, nil
}
func readPersistentFactory(dir string) (persistentFactory, bool, error) {
	b, found, e := readFactoryProtected(dir, persistentFactoryFile, 4096)
	if e != nil || !found {
		return persistentFactory{}, found, e
	}
	v, e := decodePersistentFactory(b)
	return v, true, e
}
func readPersistentFactoryJournal(dir string) ([]byte, journal, error) {
	b, found, e := readFactoryProtected(dir, "usb-host-address.json", 2048)
	if e != nil || !found {
		return nil, journal{}, errors.New("USB_HOST_FACTORY_JOURNAL_UNPROVEN")
	}
	p, e := decodeJournal(b)
	if e != nil || p.Version != 2 {
		return nil, journal{}, errors.New("USB_HOST_FACTORY_JOURNAL_UNPROVEN")
	}
	return b, p, nil
}

// The caller holds hostOperationMu and the parent cross-process configuration
// lease. A comparison immediately before Move binds the exact previous bytes.
func writeFactoryProtected(dir, name string, b []byte, previous []byte) error {
	if !removalDirectoryProtected(dir) {
		return errors.New("USB_HOST_FACTORY_DIRECTORY_UNPROVEN")
	}
	sd, e := windows.SecurityDescriptorFromString(removalFileSDDL)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	tmp := filepath.Join(dir, "usb-host-factory-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(tmp)
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(tmp), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return errors.New("USB_HOST_FACTORY_WRITE_FAILED")
	}
	f := os.NewFile(uintptr(h), tmp)
	if f == nil {
		windows.CloseHandle(h)
		return errors.New("USB_HOST_FACTORY_WRITE_FAILED")
	}
	var info windows.ByHandleFileInformation
	actual, se := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if se != nil || !removalACLMatches(actual, sd) || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		f.Close()
		return errors.New("USB_HOST_FACTORY_WRITE_PROTECTION_UNPROVEN")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("USB_HOST_FACTORY_WRITE_FAILED")
	}
	old, found, e := readFactoryProtected(dir, name, 4096)
	if e != nil {
		return e
	}
	if previous == nil && found || previous != nil && (!found || string(old) != string(previous)) {
		return errors.New("USB_HOST_FACTORY_RECORD_CHANGED")
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if previous != nil {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if windows.MoveFileEx(windows.StringToUTF16Ptr(tmp), windows.StringToUTF16Ptr(filepath.Join(dir, name)), flags) != nil {
		return errors.New("USB_HOST_FACTORY_COMMIT_FAILED")
	}
	got, found, e := readFactoryProtected(dir, name, 4096)
	if e != nil || !found || string(got) != string(b) {
		return errors.New("USB_HOST_FACTORY_READBACK_FAILED")
	}
	return nil
}
func writePersistentFactory(dir string, v persistentFactory, old *persistentFactory) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e = decodePersistentFactory(b); e != nil {
		return e
	}
	var previous []byte
	if old != nil {
		got, found, e := readPersistentFactory(dir)
		if e != nil || !found || got != *old || validatePersistentFactoryTransition(*old, v) != nil {
			return errors.New("USB_HOST_FACTORY_RECORD_CHANGED")
		}
		previous, _ = json.Marshal(old)
	} else if v.State != "ready" {
		return errors.New("USB_HOST_FACTORY_PHASE_INVALID")
	}
	return writeFactoryProtected(dir, persistentFactoryFile, b, previous)
}
func checkpointFactoryJournal(dir string, v persistentFactory) error {
	b, _, e := readPersistentFactoryJournal(dir)
	if e != nil {
		return e
	}
	next, e := persistentFactoryJournalPosition(v, b)
	if e != nil {
		return e
	}
	if next {
		return nil
	}
	n, _ := json.Marshal(v.Next)
	return writeFactoryProtected(dir, "usb-host-address.json", n, b)
}
