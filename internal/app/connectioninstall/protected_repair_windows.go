//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/platform/windows/machinepaths"
	"suhang/usbnet/internal/platform/windows/protectedacl"
)

const protectedStoreDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
const protectedStoreFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

var protectedStoreStatus atomic.Value

// ProtectedStoreDirectories are the fixed machine directories (legacy and current) whose exact
// protected DACL the core's stores verify. Explorer's "Continue" prompt adds
// the user's ACE to them, which those checks treat as tampering.
func ProtectedStoreDirectories() ([]string, error) {
	recovery, e := machinepaths.RecoveryFolder()
	if e != nil {
		return nil, e
	}
	logs, e := machinepaths.LogsFolder()
	if e != nil {
		return nil, e
	}
	// Old and new both: an upgrade can be rolled back, and a migration moves one to the other.
	return []string{recovery.Old, recovery.New, logs.Old, logs.New}, nil
}

// remoteMaintenanceDirectories are every location maintenanceBase may pick;
// the core reads one of them before it reaches the service dispatcher.
func remoteMaintenanceDirectories() []string {
	var dirs []string
	if old, e := legacyRoot(); e == nil {
		dirs = append(dirs, filepath.Join(old, "Remote Maintenance"))
	}
	if root, e := Root(); e == nil {
		dirs = append(dirs, filepath.Join(root, "Remote Maintenance"))
	}
	if data, e := machinepaths.MachineRoot(); e == nil {
		dirs = append(dirs, filepath.Join(data, "State", "Remote Maintenance"))
	}
	return dirs
}

// coreOwners are the accounts besides SYSTEM/Administrators that may own the
// stores: the installing administrator owns files an elevated installer created.
func coreOwners() []string {
	var owners []string
	if u, e := windows.GetCurrentProcessToken().GetTokenUser(); e == nil {
		owners = append(owners, u.User.Sid.String())
	}
	if b, e := CurrentCoreBinding(); e == nil {
		owners = append(owners, b.OwnerSID)
	}
	return owners
}

// RepairProtectedStores runs before any store check. Status is "passed",
// "repaired: ..." or "failed: ..."; a failure never hides the later checks.
func RepairProtectedStores() ([]protectedacl.Repair, string) {
	dirs, err := ProtectedStoreDirectories()
	var repairs []protectedacl.Repair
	var notes []string
	owners := coreOwners()
	type store struct{ dir, dirSDDL, fileSDDL string }
	var stores []store
	for _, dir := range dirs {
		stores = append(stores, store{dir, protectedStoreDirSDDL, protectedStoreFileSDDL})
	}
	// Candidate status files there are created with remoteACL itself.
	for _, dir := range remoteMaintenanceDirectories() {
		stores = append(stores, store{dir, remoteACL, remoteACL})
	}
	for _, st := range stores {
		dir := st.dir
		r, e := protectedacl.RepairProtectedDirectory(dir, st.dirSDDL, st.fileSDDL, owners...)
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
