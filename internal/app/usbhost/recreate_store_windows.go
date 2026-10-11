//go:build windows && amd64

package usbhost

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

const recreateFile = "usb-host-recreate.json"
const recreateFileSDDL = removalFileSDDL

func readRecreateTransactionFile(dir string) (recreateTransaction, bool, error) {
	var zero recreateTransaction
	if !removalDirectoryProtected(dir) {
		return zero, false, fmt.Errorf("USB_HOST_RECREATE_STORE_UNPROVEN")
	}
	path := filepath.Join(dir, recreateFile)
	p, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return zero, false, nil
	}
	if e != nil {
		return zero, false, fmt.Errorf("USB_HOST_RECREATE_INTENT_UNREADABLE")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	expected, se := windows.SecurityDescriptorFromString(recreateFileSDDL)
	if e != nil || se != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !removalACLMatches(actual, expected) {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_HOST_RECREATE_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_HOST_RECREATE_INTENT_UNREADABLE")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return zero, false, fmt.Errorf("USB_HOST_RECREATE_INTENT_UNREADABLE")
	}
	v, e := decodeRecreateTransaction(b)
	return v, true, e
}

func writeRecreateTransactionFile(dir string, v recreateTransaction, replace bool) error {
	if !removalDirectoryProtected(dir) {
		return fmt.Errorf("USB_HOST_RECREATE_STORE_UNPROVEN")
	}
	if !replace && v.State != "attempt" && v.State != "closing" {
		return fmt.Errorf("USB_HOST_RECREATE_PHASE_INVALID")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_INVALID")
	}
	if _, e = decodeRecreateTransaction(b); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(recreateFileSDDL)
	if e != nil {
		return fmt.Errorf("USB_HOST_RECREATE_ACL_UNAVAILABLE")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return fmt.Errorf("USB_HOST_RECREATE_RANDOM_FAILED")
	}
	temp := filepath.Join(dir, "usb-host-recreate-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(temp)
	tp, _ := windows.UTF16PtrFromString(temp)
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_CREATE_FAILED")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !removalACLMatches(actual, sd) {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), temp)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_WRITE_FAILED")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_WRITE_FAILED")
	}
	if replace {
		old, found, e := readRecreateTransactionFile(dir)
		if e != nil || !found || validateRecreateTransition(old, v) != nil {
			return fmt.Errorf("USB_HOST_RECREATE_INTENT_CHANGED")
		}
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	dst, _ := windows.UTF16PtrFromString(filepath.Join(dir, recreateFile))
	if windows.MoveFileEx(tp, dst, flags) != nil {
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_COMMIT_FAILED")
	}
	got, found, e := readRecreateTransactionFile(dir)
	if e != nil || !found || got != v {
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_READBACK_FAILED")
	}
	return nil
}

func clearRecreateTransactionFile(dir string, v recreateTransaction) error {
	got, found, e := readRecreateTransactionFile(dir)
	if e != nil || !found || got != v {
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_CHANGED")
	}
	if os.Remove(filepath.Join(dir, recreateFile)) != nil {
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_DELETE_FAILED")
	}
	_, found, e = readRecreateTransactionFile(dir)
	if e != nil || found {
		return fmt.Errorf("USB_HOST_RECREATE_INTENT_ABSENCE_UNCONFIRMED")
	}
	return nil
}
