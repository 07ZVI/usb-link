//go:build windows && amd64

package interfaceconfig

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"unsafe"
)

const ownedDADFile = "usb-owned-dad.json"

func readOwnedDADFile(dir string) (ownedDADLedger, bool, error) {
	var zero ownedDADLedger
	if !configDirectoryProtected(dir) {
		return zero, false, fmt.Errorf("USB_OWNED_DAD_STORE_UNPROVEN")
	}
	path := filepath.Join(dir, ownedDADFile)
	p, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return zero, false, nil
	}
	if e != nil {
		return zero, false, fmt.Errorf("USB_OWNED_DAD_INTENT_UNREADABLE")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	expected, se := windows.SecurityDescriptorFromString(configFileSDDL)
	if e != nil || se != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !configACLMatches(actual, expected) {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_OWNED_DAD_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_OWNED_DAD_INTENT_UNREADABLE")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil {
		return zero, false, fmt.Errorf("USB_OWNED_DAD_INTENT_UNREADABLE")
	}
	v, e := decodeOwnedDADLedger(b)
	return v, true, e
}

func writeOwnedDADFile(dir string, v ownedDADLedger, replace bool) error {
	if !configDirectoryProtected(dir) {
		return fmt.Errorf("USB_OWNED_DAD_STORE_UNPROVEN")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return fmt.Errorf("USB_OWNED_DAD_INTENT_INVALID")
	}
	if _, e = decodeOwnedDADLedger(b); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(configFileSDDL)
	if e != nil {
		return fmt.Errorf("USB_OWNED_DAD_ACL_UNAVAILABLE")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return fmt.Errorf("USB_OWNED_DAD_RANDOM_FAILED")
	}
	temp := filepath.Join(dir, "usb-owned-dad-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(temp)
	tp, _ := windows.UTF16PtrFromString(temp)
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fmt.Errorf("USB_OWNED_DAD_INTENT_CREATE_FAILED")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !configACLMatches(actual, sd) {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_OWNED_DAD_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), temp)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_OWNED_DAD_INTENT_WRITE_FAILED")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fmt.Errorf("USB_OWNED_DAD_INTENT_WRITE_FAILED")
	}
	if replace {
		old, found, e := readOwnedDADFile(dir)
		if e != nil || !found || !sameOwnedDADBaselines(old, v) {
			return fmt.Errorf("USB_OWNED_DAD_INTENT_CHANGED")
		}
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	dst, _ := windows.UTF16PtrFromString(filepath.Join(dir, ownedDADFile))
	if windows.MoveFileEx(tp, dst, flags) != nil {
		return fmt.Errorf("USB_OWNED_DAD_INTENT_COMMIT_FAILED")
	}
	got, found, e := readOwnedDADFile(dir)
	if e != nil || !found || !sameOwnedDADLedger(got, v) {
		return fmt.Errorf("USB_OWNED_DAD_INTENT_READBACK_FAILED")
	}
	return nil
}

func clearOwnedDADFile(dir string, v ownedDADLedger) error {
	got, found, e := readOwnedDADFile(dir)
	if e != nil || !found || !sameOwnedDADLedger(got, v) {
		return fmt.Errorf("USB_OWNED_DAD_INTENT_CHANGED")
	}
	if os.Remove(filepath.Join(dir, ownedDADFile)) != nil {
		return fmt.Errorf("USB_OWNED_DAD_INTENT_DELETE_FAILED")
	}
	_, found, e = readOwnedDADFile(dir)
	if e != nil || found {
		return fmt.Errorf("USB_OWNED_DAD_INTENT_ABSENCE_UNCONFIRMED")
	}
	return nil
}
