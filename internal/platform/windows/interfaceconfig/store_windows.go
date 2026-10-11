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
	"sort"
	"unsafe"
)

const configFile = "usb-interface-config.json"
const configFileSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
const configDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func configACLMatches(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
	if actual == nil || expected == nil {
		return false
	}
	owner, _, oe := actual.Owner()
	admin, ae := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	system, se := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if oe != nil || ae != nil || se != nil || owner == nil || (!owner.Equals(admin) && !owner.Equals(system)) {
		return false
	}
	control, _, e := actual.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	aces := func(sd *windows.SECURITY_DESCRIPTOR) ([]string, bool) {
		a, _, e := sd.DACL()
		if e != nil || a == nil || a.AceCount != 2 {
			return nil, false
		}
		var out []string
		for i := uint32(0); i < 2; i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if windows.GetAce(a, i, &ace) != nil || ace == nil || ace.Header.AceSize < 8 || ace.Header.AceSize > 64 {
				return nil, false
			}
			out = append(out, string(unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize))))
		}
		sort.Strings(out)
		return out, true
	}
	a, ok := aces(actual)
	if !ok {
		return false
	}
	b, ok := aces(expected)
	return ok && a[0] == b[0] && a[1] == b[1]
}

func configDirectoryProtected(dir string) bool {
	p, e := windows.UTF16PtrFromString(dir)
	if e != nil {
		return false
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	expected, se := windows.SecurityDescriptorFromString(configDirSDDL)
	return e == nil && se == nil && windows.GetFileInformationByHandle(h, &info) == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 && configACLMatches(actual, expected)
}

func readConfigReceiptFile(dir string) (configReceipt, bool, error) {
	var zero configReceipt
	if !configDirectoryProtected(dir) {
		return zero, false, fmt.Errorf("USB_INTERFACE_CONFIG_STORE_UNPROVEN")
	}
	path := filepath.Join(dir, configFile)
	p, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return zero, false, nil
	}
	if e != nil {
		return zero, false, fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_UNREADABLE")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	expected, se := windows.SecurityDescriptorFromString(configFileSDDL)
	if e != nil || se != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !configACLMatches(actual, expected) {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_UNREADABLE")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil {
		return zero, false, fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_UNREADABLE")
	}
	v, e := decodeConfigReceipt(b)
	return v, true, e
}

func writeConfigReceiptFile(dir string, v configReceipt, replace bool) error {
	if !configDirectoryProtected(dir) {
		return fmt.Errorf("USB_INTERFACE_CONFIG_STORE_UNPROVEN")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_INVALID")
	}
	if _, e = decodeConfigReceipt(b); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(configFileSDDL)
	if e != nil {
		return fmt.Errorf("USB_INTERFACE_CONFIG_ACL_UNAVAILABLE")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return fmt.Errorf("USB_INTERFACE_CONFIG_RANDOM_FAILED")
	}
	temp := filepath.Join(dir, "usb-interface-config-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(temp)
	tp, _ := windows.UTF16PtrFromString(temp)
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_CREATE_FAILED")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !configACLMatches(actual, sd) {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), temp)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_WRITE_FAILED")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_WRITE_FAILED")
	}
	if replace {
		old, found, e := readConfigReceiptFile(dir)
		if e != nil || !found || !sameConfigBaselines(old, v) {
			return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_CHANGED")
		}
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	dst, _ := windows.UTF16PtrFromString(filepath.Join(dir, configFile))
	if windows.MoveFileEx(tp, dst, flags) != nil {
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_COMMIT_FAILED")
	}
	got, found, e := readConfigReceiptFile(dir)
	if e != nil || !found || !sameConfigReceipt(got, v) {
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_READBACK_FAILED")
	}
	return nil
}

func clearConfigReceiptFile(dir string, v configReceipt) error {
	got, found, e := readConfigReceiptFile(dir)
	if e != nil || !found || !sameConfigReceipt(got, v) {
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_CHANGED")
	}
	if os.Remove(filepath.Join(dir, configFile)) != nil {
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_DELETE_FAILED")
	}
	_, found, e = readConfigReceiptFile(dir)
	if e != nil || found {
		return fmt.Errorf("USB_INTERFACE_CONFIG_INTENT_ABSENCE_UNCONFIRMED")
	}
	return nil
}
