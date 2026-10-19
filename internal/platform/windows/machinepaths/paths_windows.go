//go:build windows

// Package machinepaths defines, once, where the product keeps its machine
// folders: the %ProgramData%\USB Link layout and the legacy locations an
// older version (or a rollback to one) still uses.
package machinepaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

const (
	legacyRecoveryLeaf = "Suhang-iPad-Grouping-Recovery" // legacy name kept for compatibility with installed versions
	legacyLogsLeaf     = "USBLink-Core-7c494949-9688-4bd4-90c6-257e315f9550"
	machineRoot        = "USB Link"
)

var storeOpened atomic.Bool

// MarkStoreOpened records that this process opened the recovery store, after
// which no folder may be moved under it.
func MarkStoreOpened() { storeOpened.Store(true) }

// StoreOpened reports whether MarkStoreOpened ran.
func StoreOpened() bool { return storeOpened.Load() }

// Folder is one migrating machine folder.
type Folder struct{ New, Old string }

// MachineRoot is %ProgramData%\USB Link.
func MachineRoot() (string, error) {
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return "", e
	}
	return filepath.Join(data, machineRoot), nil
}

// RecoveryFolder is the recovery store: journals, receipts, locks, runtime dirs.
func RecoveryFolder() (Folder, error) {
	w, e := windows.GetWindowsDirectory()
	if e != nil {
		return Folder{}, e
	}
	root, e := MachineRoot()
	if e != nil {
		return Folder{}, e
	}
	return Folder{New: filepath.Join(root, "Recovery"), Old: filepath.Join(w, "Temp", legacyRecoveryLeaf)}, nil
}

// LogsFolder holds core.log and its marker.
func LogsFolder() (Folder, error) {
	root, e := MachineRoot()
	if e != nil {
		return Folder{}, e
	}
	return Folder{New: filepath.Join(root, "Logs"), Old: filepath.Join(filepath.Dir(root), legacyLogsLeaf)}, nil
}

func exists(path string) bool {
	_, e := os.Lstat(path)
	return e == nil || !os.IsNotExist(e) // an unreadable entry still counts as present
}

// ParentUsable reports whether path's parent is a plain directory.
func ParentUsable(path string) bool {
	a, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(filepath.Dir(path)))
	return e == nil && a&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && a&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

// Active is the folder in use right now: new if present, else old.
func (f Folder) Active() string {
	if UseNew(exists(f.New), exists(f.Old), ParentUsable(f.New)) {
		return f.New
	}
	return f.Old
}

// Both lists the active folder first, then the other one.
func (f Folder) Both() []string {
	if f.Active() == f.New {
		return []string{f.New, f.Old}
	}
	return []string{f.Old, f.New}
}

// IsActive accepts exactly the resolved active folder, nothing else.
func (f Folder) IsActive(dir string) bool {
	return dir != "" && strings.EqualFold(filepath.Clean(dir), f.Active())
}

// ActiveRecovery returns the recovery store location in use.
func ActiveRecovery() (string, error) {
	f, e := RecoveryFolder()
	return f.Active(), e
}

// IsActiveRecovery reports whether dir is exactly the active recovery store.
func IsActiveRecovery(dir string) bool {
	f, e := RecoveryFolder()
	return e == nil && f.IsActive(dir)
}

// UIDiagnostics is the per-user diagnostic zip root; legacy is the old one.
func UIDiagnostics() (current, legacy string, err error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", "", fmt.Errorf("LOCALAPPDATA unavailable")
	}
	return filepath.Join(base, "USB Link", "Diagnostics"), filepath.Join(base, "Suhang", "iPadUSBSetup"), nil
}

// SameVolume compares the drive letters of two absolute paths.
func SameVolume(a, b string) bool {
	return filepath.VolumeName(a) != "" && strings.EqualFold(filepath.VolumeName(a), filepath.VolumeName(b))
}

// Rename moves a whole directory atomically within one volume. It never
// copies: MOVEFILE_COPY_ALLOWED is deliberately absent.
func Rename(from, to string) error {
	f, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	t, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(f, t, 0)
}
