//go:build windows && amd64

package ipadncm

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
	"strings"
	"unsafe"
)

const portablePropertyFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

const portablePropertyOriginalFile = "network-only-property-originals.json"
const portableLegacyAuditFile = "network-only-legacy-value-restores.json"
const portablePropertyStoreLimit = 262144

func readPortableOriginalStore(dir string) (portableOriginalStore, error) {
	s := portableOriginalStore{Version: 1}
	if !networkOnlyDriverStoreProtected(dir) {
		return s, fmt.Errorf("portable property store protection unproven")
	}
	b, err := readPortableProtectedFile(filepath.Join(dir, portablePropertyOriginalFile), portablePropertyStoreLimit)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return decodePortableOriginalStore(b)

}
func portableOriginalMetadata(dir string, n portableNodeReceipt) (*portablePropertyOriginal, error) {
	s, err := readPortableOriginalStore(dir)
	if err != nil {
		return nil, err
	}
	return portableOriginalForReceipt(s, n)

}
func savePortableOriginalMetadata(dir string, p portablePropertyOriginal) error {
	if !p.valid() {
		return fmt.Errorf("portable original native metadata invalid")
	}
	s, err := readPortableOriginalStore(dir)
	if err != nil {
		return err
	}
	for _, old := range s.Records {
		if strings.EqualFold(old.Node.ID, p.Node.ID) {
			if !samePortableReceipt(old.Node, p.Node) || old.Present != p.Present || old.Type != p.Type || old.Size != p.Size || old.Value != p.Value {
				return fmt.Errorf("portable original native metadata changed")
			}
			return nil
		}
	}
	if len(s.Records) >= 64 {
		return fmt.Errorf("portable property original limit")
	}
	s.Records = append(s.Records, p)
	b, err := json.Marshal(s)
	if err != nil || len(b) > portablePropertyStoreLimit {
		return fmt.Errorf("portable property original encoding failed")
	}
	if err = writePortableProtectedFile(dir, portablePropertyOriginalFile, b, true); err != nil {
		return err
	}
	read, err := readPortableProtectedFile(filepath.Join(dir, portablePropertyOriginalFile), portablePropertyStoreLimit)
	if err != nil || !bytes.Equal(read, b) {
		return fmt.Errorf("portable original metadata durable readback failed")
	}
	_, err = decodePortableOriginalStore(read)
	return err
}

func readPortableLegacyAudit(dir string) (portableLegacyAuditStore, bool, error) {
	s := portableLegacyAuditStore{Version: 1}
	if !networkOnlyDriverStoreProtected(dir) {
		return s, false, fmt.Errorf("portable audit store protection unproven")
	}
	b, err := readPortableProtectedFile(filepath.Join(dir, portableLegacyAuditFile), portablePropertyStoreLimit)
	if os.IsNotExist(err) {
		return s, false, nil
	}
	if err != nil {
		return s, false, err
	}
	s, err = decodePortableLegacyAudit(b)
	return s, err == nil, err
}
func savePortableLegacyAudit(dir string, a portableLegacyValueAudit) error {
	if !a.valid() {
		return fmt.Errorf("portable restoration audit invalid")
	}
	s, _, err := readPortableLegacyAudit(dir)
	if err != nil {
		return err
	}
	s, err = upsertPortableRestoreAudit(s, a)
	if err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil || len(b) > portablePropertyStoreLimit {
		return fmt.Errorf("portable restoration audit encoding failed")
	}
	if err = writePortableProtectedFile(dir, portableLegacyAuditFile, b, true); err != nil {
		return err
	}
	read, err := readPortableProtectedFile(filepath.Join(dir, portableLegacyAuditFile), portablePropertyStoreLimit)
	if err != nil || !bytes.Equal(read, b) {
		return fmt.Errorf("portable restoration audit durable readback failed")
	}
	_, err = decodePortableLegacyAudit(read)
	return err
}
func removeCheckpointedPortableOriginals(dir string, remaining []portableNodeReceipt) error {
	s, err := readPortableOriginalStore(dir)
	if err != nil {
		return err
	}
	retained := s.Records[:0]
	for _, p := range s.Records {
		for _, n := range remaining {
			if samePortableReceipt(p.Node, n) {
				retained = append(retained, p)
				break
			}
		}
	}
	if len(retained) == len(s.Records) {
		return nil
	}
	s.Records = retained
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err = writePortableProtectedFile(dir, portablePropertyOriginalFile, b, true); err != nil {
		return err
	}
	read, err := readPortableProtectedFile(filepath.Join(dir, portablePropertyOriginalFile), portablePropertyStoreLimit)
	if err != nil || !bytes.Equal(read, b) {
		return fmt.Errorf("portable original metadata checkpoint readback failed")
	}
	return nil
}

func verifyOwnedPortableReceipt(dir string, n portableNodeReceipt) error {
	if !networkOnlyDriverStoreProtected(dir) {
		return fmt.Errorf("portable restore store protection unproven")
	}
	r, err := readNetworkOnlyReceipt(dir)
	if err != nil {
		return err
	}
	for _, old := range r.Nodes {
		if strings.EqualFold(old.ID, n.ID) {
			if samePortableReceipt(old, n) {
				return nil
			}
			return fmt.Errorf("portable restore receipt changed")
		}
	}
	return fmt.Errorf("portable restore target not owned by receipt")
}

// Private sidecars have their own protected DACL, checked on the opened handle;
// parent directory protection alone cannot legitimize an unexpected file ACL.
func readPortableProtectedFile(path string, limit int64) ([]byte, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	expected, e := windows.SecurityDescriptorFromString(portablePropertyFileSDDL)
	actual, se := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || e != nil || se != nil || !groupingACLMatches(actual, expected) {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("portable property file protection unproven")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("portable property file handle unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, fmt.Errorf("portable property file read or bound failed")
	}
	return b, nil
}
func writePortableProtectedFile(dir, name string, b []byte, replace bool) error {
	if !networkOnlyDriverStoreProtected(dir) || name != portablePropertyOriginalFile && name != portableLegacyAuditFile && name != unpairedProductOwnerFile && name != simplifiedMigrationFile {
		return fmt.Errorf("portable private store target unproven")
	}

	f, path, e := createPortableProtectedTemp(dir)
	if e != nil {
		return e
	}
	defer os.Remove(path)
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
	// Validate the exact restrictive new file before publishing it atomically.
	read, e := readPortableProtectedFile(path, portablePropertyStoreLimit)
	if e != nil || !bytes.Equal(read, b) {
		return fmt.Errorf("portable temporary property file verification failed")
	}
	from, _ := windows.UTF16PtrFromString(path)
	to, _ := windows.UTF16PtrFromString(filepath.Join(dir, name))
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(from, to, flags)
}

// CREATE_NEW plus a creation-time protected file ACL avoids both an existing
// object and the WRITE_DAC requirement of post-creation SetSecurityInfo.
func createPortableProtectedTemp(dir string) (*os.File, string, error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return nil, "", fmt.Errorf("portable temporary store protection unproven")
	}
	sd, e := windows.SecurityDescriptorFromString(portablePropertyFileSDDL)
	if e != nil {
		return nil, "", e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for attempt := 0; attempt < 16; attempt++ {
		var random [16]byte
		if _, e = rand.Read(random[:]); e != nil {
			return nil, "", e
		}
		path := filepath.Join(dir, "network-only-property-"+hex.EncodeToString(random[:])+".tmp")
		p, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return nil, "", e
		}
		h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e == windows.ERROR_FILE_EXISTS || e == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if e != nil {
			return nil, "", e
		}
		// GENERIC_READ supplies READ_CONTROL. Verify the same newly created handle
		// before writing; FA is the concrete file mapping used in the expected ACL.
		var info windows.ByHandleFileInformation
		actual, se := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || se != nil || !groupingACLMatches(actual, sd) {
			windows.CloseHandle(h)
			os.Remove(path)
			return nil, "", fmt.Errorf("portable created file protection unproven")
		}
		f := os.NewFile(uintptr(h), path)
		if f == nil {
			windows.CloseHandle(h)
			os.Remove(path)
			return nil, "", fmt.Errorf("portable created file handle unavailable")
		}
		return f, path, nil
	}
	return nil, "", fmt.Errorf("portable temporary filename collision limit")
}

// Recovery maintenance may precede InitNetworkOnly. This explicit reader takes
// only the fixed protected recovery directory and cannot initialize policy.
func ReadNetworkOnlyPropertyRestoreSummaries(recoveryDir string) ([]PortablePropertyRestoreSummary, error) {
	audit, durable, e := readPortableLegacyAudit(recoveryDir)
	if e != nil {
		return nil, fmt.Errorf("PROTECTED_PORTABLE_RESTORE_AUDIT_UNREADABLE")
	}
	return portableRestoreSummaries(audit, durable), nil
}
