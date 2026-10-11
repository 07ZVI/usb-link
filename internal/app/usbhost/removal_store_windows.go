//go:build windows && amd64

package usbhost

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
	"suhang/usbnet/internal/platform/windows/netconfig"
	"unsafe"
)

const removalFile = "usb-host-removal.json"
const removalFileSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
const removalDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func removalACLMatches(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
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

func removalDirectoryProtected(dir string) bool {
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
	expected, se := windows.SecurityDescriptorFromString(removalDirSDDL)
	return e == nil && se == nil && windows.GetFileInformationByHandle(h, &info) == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 && removalACLMatches(actual, expected)
}

func readRemovalIntentFile(dir string) (removalIntent, bool, error) {
	var zero removalIntent
	if !removalDirectoryProtected(dir) {
		return zero, false, fmt.Errorf("USB_HOST_REMOVAL_STORE_UNPROVEN")
	}
	path := filepath.Join(dir, removalFile)
	p, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return zero, false, nil
	}
	if e != nil {
		return zero, false, fmt.Errorf("USB_HOST_REMOVAL_INTENT_UNREADABLE")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	expected, se := windows.SecurityDescriptorFromString(removalFileSDDL)
	if e != nil || se != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !removalACLMatches(actual, expected) {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_HOST_REMOVAL_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return zero, false, fmt.Errorf("USB_HOST_REMOVAL_INTENT_UNREADABLE")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 2049))
	if e != nil {
		return zero, false, fmt.Errorf("USB_HOST_REMOVAL_INTENT_UNREADABLE")
	}
	v, e := decodeRemovalIntent(b)
	return v, true, e
}

func writeRemovalIntentFile(dir string, v removalIntent, replace bool) error {
	if !removalDirectoryProtected(dir) {
		return fmt.Errorf("USB_HOST_REMOVAL_STORE_UNPROVEN")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_INVALID")
	}
	if _, e = decodeRemovalIntent(b); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(removalFileSDDL)
	if e != nil {
		return fmt.Errorf("USB_HOST_REMOVAL_ACL_UNAVAILABLE")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return fmt.Errorf("USB_HOST_REMOVAL_RANDOM_FAILED")
	}
	temp := filepath.Join(dir, "usb-host-removal-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(temp)
	tp, _ := windows.UTF16PtrFromString(temp)
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_CREATE_FAILED")
	}
	var info windows.ByHandleFileInformation
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || !removalACLMatches(actual, sd) {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), temp)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_WRITE_FAILED")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_WRITE_FAILED")
	}
	if replace {
		old, found, e := readRemovalIntentFile(dir)
		if e != nil || !found || old.JournalSHA256 != v.JournalSHA256 || old.Instance != v.Instance || old.Ticks != v.Ticks {
			return fmt.Errorf("USB_HOST_REMOVAL_INTENT_CHANGED")
		}
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	dst, _ := windows.UTF16PtrFromString(filepath.Join(dir, removalFile))
	if windows.MoveFileEx(tp, dst, flags) != nil {
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_COMMIT_FAILED")
	}
	got, found, e := readRemovalIntentFile(dir)
	if e != nil || !found || got != v {
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_READBACK_FAILED")
	}
	return nil
}

func clearRemovalIntentFile(dir string, v removalIntent) error {
	got, found, e := readRemovalIntentFile(dir)
	if e != nil || !found || got != v {
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_CHANGED")
	}
	if os.Remove(filepath.Join(dir, removalFile)) != nil {
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_DELETE_FAILED")
	}
	_, found, e = readRemovalIntentFile(dir)
	if e != nil || found {
		return fmt.Errorf("USB_HOST_REMOVAL_INTENT_ABSENCE_UNCONFIRMED")
	}
	return nil
}

func systemTicks() uint64 {
	v, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64").Call()
	return uint64(v)
}

func finishRemoval(dir, path string, v removalIntent, b []byte, journalPresent bool) error {
	if e := removalRecoveryGate(v, b, journalPresent, systemTicks()); e != nil {
		return e
	}
	absent, e := netconfig.ConfirmSharedHostRemovalAbsentNative(v.Instance)
	if e != nil || !absent {
		return fmt.Errorf("USB_HOST_REMOVAL_ABSENCE_UNCONFIRMED")
	}
	if v.State != "complete" {
		v.State = "complete"
		if e = writeRemovalIntentFile(dir, v, true); e != nil {
			return e
		}
	}
	if journalPresent {
		current, e := readHostDiagnosticJournal(path)
		if e != nil || !bytes.Equal(current, b) {
			return fmt.Errorf("USB_HOST_REMOVAL_JOURNAL_CHANGED")
		}
		if os.Remove(path) != nil {
			return fmt.Errorf("USB_HOST_JOURNAL_DELETE_FAILED")
		}
	}
	return clearRemovalIntentFile(dir, v)
}
