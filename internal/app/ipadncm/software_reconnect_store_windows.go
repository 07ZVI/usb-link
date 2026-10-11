//go:build windows && amd64

package ipadncm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
	"unsafe"
)

const softwareReconnectFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

type softwareReconnectStore struct {
	dir                      string
	directory, lock, receipt windows.Handle
}

func softwareTrustedHandle(h windows.Handle, folder bool) error {
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil {
		return e
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || folder != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) || (!folder && info.NumberOfLinks != 1) {
		return fmt.Errorf("software reconnect recovery object unsafe")
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	expected := softwareReconnectFileSDDL
	if folder {
		expected = groupingSDDL
	}
	want, e := windows.SecurityDescriptorFromString(expected)
	if e != nil || !groupingACLMatches(sd, want) {
		return fmt.Errorf("software reconnect recovery ACL changed")
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil {
		return fmt.Errorf("software reconnect recovery owner unavailable")
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sid := owner.String()
	if sid != "S-1-5-18" && sid != "S-1-5-32-544" && sid != user.User.Sid.String() {
		return fmt.Errorf("software reconnect recovery owner unexpected")
	}
	return nil
}
func openSoftwareReconnectStore(dir string) (s *softwareReconnectStore, err error) {
	w, e := windows.GetWindowsDirectory()
	if e != nil {
		return nil, e
	}
	fixed := filepath.Join(w, "Temp", "Suhang-iPad-Grouping-Recovery")
	if !strings.EqualFold(filepath.Clean(dir), fixed) {
		return nil, fmt.Errorf("software reconnect requires fixed protected recovery store")
	}
	p, e := windows.UTF16PtrFromString(fixed)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if e != nil {
		return nil, e
	}
	s = &softwareReconnectStore{dir: fixed, directory: h}
	opened := s
	defer func() {
		if err != nil {
			opened.Close()
		}
	}()
	if e := softwareTrustedHandle(h, true); e != nil {
		return nil, e
	}
	sd, e := windows.SecurityDescriptorFromString(softwareReconnectFileSDDL)
	if e != nil {
		return nil, e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	lp, _ := windows.UTF16PtrFromString(filepath.Join(fixed, "ipad-software-reconnect.lock"))
	s.lock, e = windows.CreateFile(lp, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, &sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	if e := softwareTrustedHandle(s.lock, false); e != nil {
		return nil, e
	}
	return s, nil
}
func (s *softwareReconnectStore) Close() {
	for _, h := range []windows.Handle{s.receipt, s.lock, s.directory} {
		if h != 0 && h != windows.InvalidHandle {
			windows.CloseHandle(h)
		}
	}
	s.receipt, s.lock, s.directory = 0, 0, 0
}
func (s *softwareReconnectStore) Read() (softwareReconnectJournal, error) {
	var j softwareReconnectJournal
	if s.receipt != 0 {
		return j, fmt.Errorf("software reconnect receipt already open")
	}
	p, _ := windows.UTF16PtrFromString(filepath.Join(s.dir, softwareReconnectReceiptName))
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL|windows.DELETE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return j, e
	}
	s.receipt = h
	if e := softwareTrustedHandle(h, false); e != nil {
		return j, e
	}
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil {
		return j, e
	}
	if info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > softwareReconnectReceiptLimit {
		return j, fmt.Errorf("software reconnect receipt size invalid")
	}
	b := make([]byte, info.FileSizeLow)
	var n uint32
	if e := windows.ReadFile(h, b, &n, nil); e != nil || n != info.FileSizeLow {
		return j, fmt.Errorf("software reconnect receipt read incomplete")
	}
	return decodeSoftwareReconnectJournal(b)
}
func (s *softwareReconnectStore) Save(j softwareReconnectJournal) error {
	if !j.valid() {
		return fmt.Errorf("software reconnect target receipt invalid")
	}
	b, e := json.Marshal(j)
	if e != nil || len(b) > softwareReconnectReceiptLimit {
		return fmt.Errorf("software reconnect receipt encoding failed")
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	name := filepath.Join(s.dir, "ipad-software-reconnect-"+hex.EncodeToString(nonce[:])+".tmp")
	p, _ := windows.UTF16PtrFromString(name)
	sd, e := windows.SecurityDescriptorFromString(softwareReconnectFileSDDL)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(p, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.DELETE, windows.FILE_SHARE_DELETE, &sa, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if e != nil {
		return e
	}
	failed := true
	defer func() {
		if failed && h != 0 {
			flag := byte(1)
			_ = windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &flag, 1)
		}
		if h != 0 {
			windows.CloseHandle(h)
		}
	}()
	if e := softwareTrustedHandle(h, false); e != nil {
		return e
	}
	var n uint32
	if e := windows.WriteFile(h, b, &n, nil); e != nil || int(n) != len(b) {
		return fmt.Errorf("software reconnect receipt write incomplete")
	}
	if e := windows.FlushFileBuffers(h); e != nil {
		return e
	}
	to, _ := windows.UTF16PtrFromString(filepath.Join(s.dir, softwareReconnectReceiptName))
	if e := windows.MoveFileEx(p, to, windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	failed = false
	if e := windows.CloseHandle(h); e != nil {
		return e
	}
	h = 0
	actual, e := s.Read()
	if e != nil {
		return e
	}
	expected, _ := json.Marshal(j)
	got, _ := json.Marshal(actual)
	if string(expected) != string(got) {
		return fmt.Errorf("software reconnect receipt durable readback differs")
	}
	return nil
}
func (s *softwareReconnectStore) Remove() error {
	if s.receipt == 0 {
		return fmt.Errorf("software reconnect verified receipt handle unavailable")
	}
	flag := byte(1)
	if e := windows.SetFileInformationByHandle(s.receipt, windows.FileDispositionInfo, &flag, 1); e != nil {
		return e
	}
	e := windows.CloseHandle(s.receipt)
	s.receipt = 0
	return e
}
