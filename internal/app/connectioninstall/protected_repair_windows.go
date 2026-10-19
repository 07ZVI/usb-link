//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/platform/windows/protectedacl"
)

const protectedStoreDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
const protectedStoreFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
const groupingRecoveryDirectory = "Suhang-iPad-Grouping-Recovery"

var protectedStoreStatus atomic.Value

// ProtectedStoreDirectories are the fixed machine directories whose exact
// protected DACL the core's stores verify. Explorer's "Continue" prompt adds
// the user's ACE to them, which those checks treat as tampering.
func ProtectedStoreDirectories() ([]string, error) {
	w, e := windows.GetWindowsDirectory()
	if e != nil {
		return nil, e
	}
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return nil, e
	}
	return []string{filepath.Join(w, "Temp", groupingRecoveryDirectory), filepath.Join(data, coreLogDirectory)}, nil
}

// RepairProtectedStores runs before any store check. Status is "passed",
// "repaired: ..." or "failed: ..."; a failure never hides the later checks.
func RepairProtectedStores() ([]protectedacl.Repair, string) {
	dirs, err := ProtectedStoreDirectories()
	var repairs []protectedacl.Repair
	var notes []string
	// The installing administrator owns files an elevated installer created.
	var owners []string
	if u, e := windows.GetCurrentProcessToken().GetTokenUser(); e == nil {
		owners = append(owners, u.User.Sid.String())
	}
	if b, e := CurrentCoreBinding(); e == nil {
		owners = append(owners, b.OwnerSID)
	}
	for _, dir := range dirs {
		r, e := protectedacl.RepairProtectedDirectory(dir, protectedStoreDirSDDL, protectedStoreFileSDDL, owners...)
		if e != nil {
			err = errors.Join(err, fmt.Errorf("%s: %w", dir, e))
			continue
		}
		repairs = append(repairs, r)
		if r.Repaired() {
			notes = append(notes, r.String())
		}
	}
	status := "passed"
	switch {
	case err != nil:
		status = "failed: " + strings.ReplaceAll(err.Error(), "\n", "; ")
		if len(notes) > 0 {
			status += " | repaired: " + strings.Join(notes, "; ")
		}
	case len(notes) > 0:
		status = "repaired: " + strings.Join(notes, "; ")
	}
	protectedStoreStatus.Store(status)
	return repairs, status
}

// ProtectedStoreRepairStatus is the last repair outcome of this process.
func ProtectedStoreRepairStatus() string {
	if s, ok := protectedStoreStatus.Load().(string); ok {
		return s
	}
	return "not run"
}
