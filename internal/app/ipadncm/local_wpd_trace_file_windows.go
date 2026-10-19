//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

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
