//go:build windows && amd64

package netconfig

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"sort"
	"suhang/usbnet/internal/platform/windows/machinepaths"
	"unsafe"
)

const residentFileSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
const residentDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func residentACLMatches(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
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

func residentDirectoryProtected(dir string) bool {
	if !machinepaths.IsActiveRecovery(dir) {
		return false
	}
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
	expected, se := windows.SecurityDescriptorFromString(residentDirSDDL)
	return e == nil && se == nil && windows.GetFileInformationByHandle(h, &info) == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 && residentACLMatches(actual, expected)
}

func readResidentLedgerFile(dir, role string) ([]byte, bool, error) {
	var zero []byte
	if !residentDirectoryProtected(dir) {
		return zero, false, fmt.Errorf("USB_RESIDENT_STORE_UNPROVEN")
	}
	leaf, e := residentLeaf(role)
	if e != nil {
		return nil, false, e
	}
	path := filepath.Join(dir, leaf)
	p, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return zero, false, nil
	}
	if e != nil {
		return zero, false, fmt.Errorf("USB_RESIDENT_INTENT_UNREADABLE")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	expected, se := windows.SecurityDescriptorFromString(residentFileSDDL)
	if e != nil || se != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !residentACLMatches(actual, expected) {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_RESIDENT_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_RESIDENT_INTENT_UNREADABLE")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, residentLedgerLimit+1))
	if e != nil {
		return zero, false, fmt.Errorf("USB_RESIDENT_INTENT_UNREADABLE")
	}
	v, e := decodeResidentLedger(b)
	if e == nil && v.Role != role {
		e = fmt.Errorf("USB_RESIDENT_LEDGER_ROLE_CHANGED")
	}
	return b, true, e
}

func writeResidentLedgerFile(dir string, v residentLedger, expected []byte) error {
	if !residentDirectoryProtected(dir) {
		return fmt.Errorf("USB_RESIDENT_STORE_UNPROVEN")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e = decodeResidentLedger(b); e != nil {
		return e
	}
	leaf, e := residentLeaf(v.Role)
	if e != nil {
		return e
	}
	old, found, e := readResidentLedgerFile(dir, v.Role)
	if e != nil || (expected == nil && found) || (expected != nil && (!found || !bytes.Equal(old, expected))) {
		return fmt.Errorf("USB_RESIDENT_LEDGER_CHANGED")
	}
	sd, e := windows.SecurityDescriptorFromString(residentFileSDDL)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [12]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	tmp := filepath.Join(dir, "resident-firewall-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(tmp)
	tp, _ := windows.UTF16PtrFromString(tmp)
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), tmp)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_RESIDENT_WRITE_FAILED")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	old, found, e = readResidentLedgerFile(dir, v.Role)
	if e != nil || (expected == nil && found) || (expected != nil && (!found || !bytes.Equal(old, expected))) {
		return fmt.Errorf("USB_RESIDENT_LEDGER_CHANGED")
	}
	dst, _ := windows.UTF16PtrFromString(filepath.Join(dir, leaf))
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if expected != nil {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if e = windows.MoveFileEx(tp, dst, flags); e != nil {
		return e
	}
	got, found, e := readResidentLedgerFile(dir, v.Role)
	if e != nil || !found || !bytes.Equal(got, b) {
		return fmt.Errorf("USB_RESIDENT_LEDGER_READBACK_FAILED")
	}
	return nil
}
func clearResidentLedgerFile(dir, role string, expected []byte) error {
	b, found, e := readResidentLedgerFile(dir, role)
	if e != nil || !found || !bytes.Equal(b, expected) {
		return fmt.Errorf("USB_RESIDENT_LEDGER_CHANGED")
	}
	leaf, _ := residentLeaf(role)
	if e = os.Remove(filepath.Join(dir, leaf)); e != nil {
		return e
	}
	_, found, e = readResidentLedgerFile(dir, role)
	if e != nil || found {
		return fmt.Errorf("USB_RESIDENT_LEDGER_ABSENCE_UNPROVEN")
	}
	return nil
}
