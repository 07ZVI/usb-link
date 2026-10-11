//go:build windows && amd64

package interfaceconfig

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"unsafe"
)

const secondaryBindingFile = "usb-mac-persistent-binding.json"

func readSecondaryBinding(dir string) (secondaryBinding, bool, error) {
	var zero secondaryBinding
	if !configDirectoryProtected(dir) {
		return zero, false, errors.New("USB_SECONDARY_BINDING_STORE_UNPROVEN")
	}
	p, _ := windows.UTF16PtrFromString(filepath.Join(dir, secondaryBindingFile))
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return zero, false, nil
	}
	if e != nil {
		return zero, false, errors.New("USB_SECONDARY_BINDING_UNREADABLE")
	}
	f := os.NewFile(uintptr(h), secondaryBindingFile)
	if f == nil {
		windows.CloseHandle(h)
		return zero, false, errors.New("USB_SECONDARY_BINDING_UNREADABLE")
	}
	defer f.Close()
	if !secondaryHandleProtected(h) {
		return zero, false, errors.New("USB_SECONDARY_BINDING_PROTECTION_UNPROVEN")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return zero, false, errors.New("USB_SECONDARY_BINDING_UNREADABLE")
	}
	v, e := decodeSecondaryBinding(b)
	return v, true, e
}
func secondaryHandleProtected(h windows.Handle) bool {
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	expected, se := windows.SecurityDescriptorFromString(configFileSDDL)
	return e == nil && se == nil && windows.GetFileInformationByHandle(h, &info) == nil && info.NumberOfLinks == 1 && info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) == 0 && configACLMatches(actual, expected)
}
func writeSecondaryBinding(dir string, next secondaryBinding, old *secondaryBinding) error {
	if !configDirectoryProtected(dir) {
		return errors.New("USB_SECONDARY_BINDING_STORE_UNPROVEN")
	}
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if _, e = decodeSecondaryBinding(b); e != nil {
		return e
	}
	current, found, e := readSecondaryBinding(dir)
	if e != nil {
		return e
	}
	if old == nil {
		if found || next.State != "ready" || next.OriginalScope != next.CurrentScope {
			return errors.New("USB_SECONDARY_BINDING_ALREADY_EXISTS")
		}
	} else if !found || current != *old || secondaryTransition(current, next) != nil {
		return errors.New("USB_SECONDARY_BINDING_CHANGED")
	}
	sd, e := windows.SecurityDescriptorFromString(configFileSDDL)
	if e != nil {
		return errors.New("USB_SECONDARY_BINDING_ACL_UNPROVEN")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	temp := filepath.Join(dir, "usb-mac-binding-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(temp)
	tp, _ := windows.UTF16PtrFromString(temp)
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return errors.New("USB_SECONDARY_BINDING_CREATE_FAILED")
	}
	f := os.NewFile(uintptr(h), temp)
	if f == nil {
		windows.CloseHandle(h)
		return errors.New("USB_SECONDARY_BINDING_WRITE_FAILED")
	}
	if !secondaryHandleProtected(h) {
		f.Close()
		return errors.New("USB_SECONDARY_BINDING_PROTECTION_UNPROVEN")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("USB_SECONDARY_BINDING_WRITE_FAILED")
	}
	check, present, e := readSecondaryBinding(dir)
	if e != nil || (old == nil && present) || (old != nil && (!present || check != *old)) {
		return errors.New("USB_SECONDARY_BINDING_CHANGED")
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if old != nil {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	dst, _ := windows.UTF16PtrFromString(filepath.Join(dir, secondaryBindingFile))
	if windows.MoveFileEx(tp, dst, flags) != nil {
		return errors.New("USB_SECONDARY_BINDING_COMMIT_FAILED")
	}
	got, present, e := readSecondaryBinding(dir)
	x, _ := json.Marshal(got)
	if e != nil || !present || !bytes.Equal(x, b) {
		return errors.New("USB_SECONDARY_BINDING_READBACK_FAILED")
	}
	return nil
}
func exactSecondaryOriginal(dir string, v secondaryBinding) (persistentOriginal, error) {
	return exactSecondaryOriginalForMode(dir, v, false)
}
func exactSecondaryOriginalForMode(dir string, v secondaryBinding, restore bool) (persistentOriginal, error) {
	store, found, e := readConfigReceiptFile(dir)
	if e != nil || !found || store.RestoreRequested != restore {
		return persistentOriginal{}, errors.New("USB_SECONDARY_ORIGINAL_UNPROVEN")
	}
	for _, o := range store.Persistent {
		if o.Scope == v.OriginalScope && persistentDigest(o) == v.OriginalSHA256 && o.AppliedAddress != nil && o.Profile != nil {
			return o, nil
		}
	}
	return persistentOriginal{}, errors.New("USB_SECONDARY_ORIGINAL_CHANGED")
}

// Caller already holds lockConfig. A mapping receipt is never a driver or USB
// authorization; fresh(ctx) plus the owner's native callback still must pass.
func persistentScopeMatches(dir string, o persistentOriginal, s Scope) bool {
	if s.Role != "mac" {
		return o.Scope == s
	}
	v, found, e := readSecondaryBinding(dir)
	if e != nil {
		return false
	}
	if !found {
		return o.Scope == s
	}
	if secondaryCurrentMatches(v, o, s) {
		return true
	}
	return secondaryProjectionMatches(v, o, s) && netconfig.VerifyOwnedMacRecreatedNative(s.Index, s.LUID, v.Instance) == nil
}
