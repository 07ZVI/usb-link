//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

func openLocalAMDSHoldLease(dir string) (windows.Handle, error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return 0, amdsHoldError("AMDS_HOLD_STORE_UNPROVEN", 0)
	}
	sd, e := windows.SecurityDescriptorFromString(portablePropertyFileSDDL)
	if e != nil {
		return 0, amdsHoldError("AMDS_HOLD_STORE_UNPROVEN", 0)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(filepath.Join(dir, "local-amds-hold.lock"))
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return 0, amdsHoldError("AMDS_HOLD_OWNER_BUSY", uint32(amdsHoldNativeCode(e)))
	}
	if softwareTrustedHandle(h, false) != nil {
		windows.CloseHandle(h)
		return 0, amdsHoldError("AMDS_HOLD_STORE_UNPROVEN", 0)
	}
	return h, nil
}
func amdsHoldNativeCode(e error) uint32 {
	if n, ok := e.(windows.Errno); ok {
		return uint32(n)
	}
	return 0
}
func readLocalAMDSHoldJournal(dir string) (localAMDSHoldJournal, error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return localAMDSHoldJournal{}, amdsHoldError("AMDS_HOLD_STORE_UNPROVEN", 0)
	}
	b, e := readPortableProtectedFile(filepath.Join(dir, localAMDSHoldJournalFile), localAMDSHoldJournalLimit)
	if e != nil {
		return localAMDSHoldJournal{}, e
	}
	return decodeLocalAMDSHoldJournal(b)
}
func writeLocalAMDSHoldJournal(dir string, j localAMDSHoldJournal) error {
	if !j.valid() || !networkOnlyDriverStoreProtected(dir) {
		return amdsHoldError("AMDS_HOLD_STORE_UNPROVEN", 0)
	}
	if _, e := readLocalAMDSHoldJournal(dir); e != nil && !os.IsNotExist(e) {
		return amdsHoldError("AMDS_HOLD_JOURNAL_UNPROVEN", 0)
	}
	b, e := json.Marshal(j)
	if e != nil || len(b) > localAMDSHoldJournalLimit {
		return amdsHoldError("AMDS_HOLD_JOURNAL_INVALID", 0)
	}
	f, temp, e := createPortableProtectedTemp(dir)
	if e != nil {
		return amdsHoldError("AMDS_HOLD_JOURNAL_WRITE_FAILED", amdsHoldNativeCode(e))
	}
	defer os.Remove(temp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return amdsHoldError("AMDS_HOLD_JOURNAL_WRITE_FAILED", amdsHoldNativeCode(e))
	}
	rb, e := readPortableProtectedFile(temp, localAMDSHoldJournalLimit)
	if e != nil || !bytes.Equal(b, rb) {
		return amdsHoldError("AMDS_HOLD_JOURNAL_READBACK_FAILED", 0)
	}
	if !networkOnlyDriverStoreProtected(dir) {
		return amdsHoldError("AMDS_HOLD_STORE_UNPROVEN", 0)
	}
	e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(filepath.Join(dir, localAMDSHoldJournalFile)), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	if e != nil {
		return amdsHoldError("AMDS_HOLD_JOURNAL_WRITE_FAILED", amdsHoldNativeCode(e))
	}
	rb, e = readPortableProtectedFile(filepath.Join(dir, localAMDSHoldJournalFile), localAMDSHoldJournalLimit)
	if e != nil || !bytes.Equal(rb, b) {
		return amdsHoldError("AMDS_HOLD_JOURNAL_READBACK_FAILED", 0)
	}
	return nil
}
