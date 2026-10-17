//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

func openLocalWPDTraceLease(dir string) (windows.Handle, error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return 0, wpdTraceError("WPD_TRACE_STORE_UNPROVEN", 0)
	}
	sd, e := windows.SecurityDescriptorFromString(portablePropertyFileSDDL)
	if e != nil {
		return 0, wpdTraceError("WPD_TRACE_STORE_UNPROVEN", 0)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(filepath.Join(dir, "local-wpd-trace.lock"))
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return 0, wpdTraceError("WPD_TRACE_OWNER_BUSY", uint32(wpdNativeCode(e)))
	}
	if softwareTrustedHandle(h, false) != nil {
		windows.CloseHandle(h)
		return 0, wpdTraceError("WPD_TRACE_STORE_UNPROVEN", 0)
	}
	return h, nil
}

// The caller owns the share-zero directory lease. Pin the directory and receipt
// without delete sharing, compare the bytes through that handle, then delete
// that exact handle instead of following a path that could have been replaced.
func removeCompletedWPDMetadataJournal(dir string, lease windows.Handle, expected localWPDTraceJournal) error {
	fail := func() error { return wpdTraceError("WPD_TRACE_JOURNAL_CLEANUP_UNCONFIRMED", 0) }
	if lease == 0 || softwareTrustedHandle(lease, false) != nil || !networkOnlyDriverStoreProtected(dir) {
		return fail()
	}
	var name [32768]uint16
	n, e := windows.GetFinalPathNameByHandle(lease, &name[0], uint32(len(name)), 0)
	if e != nil || n == 0 || n >= uint32(len(name)) || !strings.EqualFold(strings.TrimPrefix(windows.UTF16ToString(name[:n]), `\\?\`), filepath.Join(dir, "local-wpd-trace.lock")) {
		return fail()
	}
	dh, e := windows.CreateFile(windows.StringToUTF16Ptr(dir), windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if e != nil {
		return fail()
	}
	defer windows.CloseHandle(dh)
	if softwareTrustedHandle(dh, true) != nil {
		return fail()
	}
	path := filepath.Join(dir, localWPDTraceJournalFile)
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.DELETE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fail()
	}
	defer func() {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}()
	if softwareTrustedHandle(h, false) != nil {
		return fail()
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > localWPDTraceJournalLimit {
		return fail()
	}
	raw := make([]byte, int(info.FileSizeLow))
	var read uint32
	if windows.ReadFile(h, raw, &read, nil) != nil || read != info.FileSizeLow || !wpdCompletedMetadataMatches(raw, expected) {
		return fail()
	}
	if _, active, err := queryLocalWPDTrace(expected, ""); err != nil || active {
		return fail()
	}
	if !networkOnlyDriverStoreProtected(dir) || softwareTrustedHandle(h, false) != nil || softwareTrustedHandle(lease, false) != nil {
		return fail()
	}
	flag := byte(1)
	if windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &flag, 1) != nil {
		return fail()
	}
	closing := h
	h = 0
	if windows.CloseHandle(closing) != nil {
		return fail()
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return fail()
	}
	return nil
}
func wpdNativeCode(e error) uint32 {
	if n, ok := e.(windows.Errno); ok {
		return uint32(n)
	}
	return 0
}
func readLocalWPDTraceJournal(dir string) (localWPDTraceJournal, error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return localWPDTraceJournal{}, wpdTraceError("WPD_TRACE_STORE_UNPROVEN", 0)
	}
	b, e := readPortableProtectedFile(filepath.Join(dir, localWPDTraceJournalFile), localWPDTraceJournalLimit)
	if e != nil {
		return localWPDTraceJournal{}, e
	}
	return decodeLocalWPDTraceJournal(b)
}
func writeLocalWPDTraceJournal(dir string, j localWPDTraceJournal) error {
	if !j.valid() || !networkOnlyDriverStoreProtected(dir) {
		return wpdTraceError("WPD_TRACE_STORE_UNPROVEN", 0)
	}
	if _, e := readLocalWPDTraceJournal(dir); e != nil && !os.IsNotExist(e) {
		return wpdTraceError("WPD_TRACE_JOURNAL_UNPROVEN", 0)
	}
	b, e := json.Marshal(j)
	if e != nil || len(b) > localWPDTraceJournalLimit {
		return wpdTraceError("WPD_TRACE_JOURNAL_INVALID", 0)
	}
	f, temp, e := createPortableProtectedTemp(dir)
	if e != nil {
		return wpdTraceError("WPD_TRACE_JOURNAL_WRITE_FAILED", wpdNativeCode(e))
	}
	defer os.Remove(temp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return wpdTraceError("WPD_TRACE_JOURNAL_WRITE_FAILED", wpdNativeCode(e))
	}
	rb, e := readPortableProtectedFile(temp, localWPDTraceJournalLimit)
	if e != nil || !bytes.Equal(b, rb) {
		return wpdTraceError("WPD_TRACE_JOURNAL_READBACK_FAILED", 0)
	}
	if !networkOnlyDriverStoreProtected(dir) {
		return wpdTraceError("WPD_TRACE_STORE_UNPROVEN", 0)
	}
	e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(filepath.Join(dir, localWPDTraceJournalFile)), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	if e != nil {
		return wpdTraceError("WPD_TRACE_JOURNAL_WRITE_FAILED", wpdNativeCode(e))
	}
	rb, e = readPortableProtectedFile(filepath.Join(dir, localWPDTraceJournalFile), localWPDTraceJournalLimit)
	if e != nil || !bytes.Equal(rb, b) {
		return wpdTraceError("WPD_TRACE_JOURNAL_READBACK_FAILED", 0)
	}
	return nil
}

// The fixed ETL is reused only when the protected journal owns that exact file.
// Unknown files are never overwritten. Re-enabling replaces the last local trace.
func preflightLocalWPDTraceFile(dir string, previous localWPDTraceJournal) error {
	path := filepath.Join(dir, localWPDTraceETLFile)
	if _, e := os.Lstat(path); e == nil {
		if !previous.valid() || previous.Schema != 1 || previous.File != localWPDTraceETLFile || !previous.Stopped {
			return wpdTraceError("WPD_TRACE_ETL_UNOWNED", 0)
		}
		return verifyLocalWPDTraceFile(path)
	} else if !os.IsNotExist(e) {
		return wpdTraceError("WPD_TRACE_ETL_UNPROVEN", wpdNativeCode(e))
	}
	return nil
}
func prepareLocalWPDTraceFile(dir string, previous localWPDTraceJournal) error {
	if e := preflightLocalWPDTraceFile(dir, previous); e != nil {
		return e
	}
	path := filepath.Join(dir, localWPDTraceETLFile)
	if _, e := os.Lstat(path); e == nil {
		return nil
	} else if !os.IsNotExist(e) {
		return wpdTraceError("WPD_TRACE_ETL_UNPROVEN", wpdNativeCode(e))
	}
	f, temp, e := createPortableProtectedTemp(dir)
	if e != nil {
		return wpdTraceError("WPD_TRACE_ETL_CREATE_FAILED", wpdNativeCode(e))
	}
	defer os.Remove(temp)
	if e = f.Close(); e != nil {
		return wpdTraceError("WPD_TRACE_ETL_CREATE_FAILED", wpdNativeCode(e))
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return wpdTraceError("WPD_TRACE_ETL_CREATE_FAILED", wpdNativeCode(e))
	}
	return verifyLocalWPDTraceFile(path)
}
func verifyLocalWPDTraceFile(path string) error {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return wpdTraceError("WPD_TRACE_ETL_UNPROVEN", 0)
	}
	h, e := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return wpdTraceError("WPD_TRACE_ETL_UNPROVEN", wpdNativeCode(e))
	}
	defer windows.CloseHandle(h)
	if softwareTrustedHandle(h, false) != nil {
		return wpdTraceError("WPD_TRACE_ETL_UNPROVEN", 0)
	}
	return nil
}
