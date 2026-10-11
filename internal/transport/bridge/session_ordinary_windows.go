//go:build windows && amd64

package bridge

import (
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
)

// ReadOrdinaryOwnedSession is a bounded read of the existing fixed leaf. The
// current ordinary writer inherits its ACL: inheritance is allowed only when
// the same exact BA/SY-only owner/full-access policy remains intact. Retained
// record protection still requires its own protected DACL and is unchanged.
func ReadOrdinaryOwnedSession(dir string) (OwnedSession, error) {
	var zero OwnedSession
	if !retainedRuntimeProtected(dir) {
		return zero, errors.New("MAC_ORDINARY_RUNTIME_UNPROVEN")
	}
	p, err := windows.UTF16PtrFromString(filepath.Join(dir, "owned-session.json"))
	if err != nil {
		return zero, errors.New("MAC_ORDINARY_RECORD_UNREADABLE")
	}
	// Deny concurrent writes and deletion while examining the same real object.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return zero, errors.New("MAC_ORDINARY_RECORD_UNREADABLE")
	}
	f := os.NewFile(uintptr(h), "owned-session.json")
	if f == nil {
		windows.CloseHandle(h)
		return zero, errors.New("MAC_ORDINARY_RECORD_UNREADABLE")
	}
	defer f.Close()
	if !retainedHandleProtected(h, false, false) {
		return zero, errors.New("MAC_ORDINARY_RECORD_PROTECTION_UNPROVEN")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return zero, errors.New("MAC_ORDINARY_RECORD_UNREADABLE")
	}
	if !retainedHandleProtected(h, false, false) || !retainedRuntimeProtected(dir) {
		return zero, errors.New("MAC_ORDINARY_RECORD_PROTECTION_UNPROVEN")
	}
	return ParseOrdinarySession(b)
}
