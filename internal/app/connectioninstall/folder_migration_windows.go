//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"suhang/usbnet/internal/diagnostics/coreterm"
	"suhang/usbnet/internal/platform/windows/machinepaths"
	"suhang/usbnet/internal/platform/windows/protectedacl"
)

// installationUnfinished is readable from the SYSTEM core, unlike
// LocalInstallationActive, which only answers for the installing user.
func installationUnfinished() (unfinished, unreadable bool) {
	t, present, e := readInstallationTransaction()
	if e != nil {
		return false, true
	}
	return present && InstallationPhaseActive(t.Phase), false
}

func lstatExists(path string) bool {
	_, e := os.Lstat(path)
	return e == nil || !os.IsNotExist(e)
}

// MigrateMachineFolders is the SYSTEM core's one-time move of the legacy
// recovery and log folders to %ProgramData%\USB Link. It runs after
// RepairProtectedStores and before any store opens. A move is one same-volume
// directory rename of the whole folder; every other outcome keeps the old
// folder in use, and nothing is ever copied or deleted. The returned lines are
// for the core log, which is not open yet.
func MigrateMachineFolders(repairs []protectedacl.Repair) []string {
	unfinished, unreadable := installationUnfinished()
	var lines []string
	move := func(label string, folder machinepaths.Folder, e error, record bool) {
		if e != nil {
			lines = append(lines, fmt.Sprintf("%s_STORE_MIGRATION_SKIPPED reason=paths_unavailable", label))
			return
		}
		repaired := false
		for _, r := range repairs {
			repaired = repaired || (strings.EqualFold(r.Path, folder.Old) && !r.Missing)
		}
		m := machinepaths.Migration{
			InstallUnfinished: unfinished, TransactionErr: unreadable,
			OldExists: lstatExists(folder.Old), NewExists: lstatExists(folder.New),
			OldRepaired: repaired, SameVolume: machinepaths.SameVolume(folder.Old, folder.New),
			ParentsPlain: noReparse(filepath.Dir(folder.Old)) == nil && noReparse(filepath.Dir(folder.New)) == nil,
			StoreOpened:  machinepaths.StoreOpened(),
		}
		reason := m.Admit()
		if reason == "" {
			if e := machinepaths.Rename(folder.Old, folder.New); e != nil {
				reason = "rename_failed: " + e.Error()
			} else if r, e := protectedacl.RepairProtectedDirectory(folder.New, protectedStoreDirSDDL, protectedStoreFileSDDL, coreOwners()...); e != nil {
				// The new folder cannot be proven protected; put it back where older versions look.
				reason = "protection_unverified_after_move: " + e.Error()
				if back := machinepaths.Rename(folder.New, folder.Old); back != nil {
					reason += "; rollback_failed: " + back.Error()
				}
			} else {
				line := fmt.Sprintf("%s_STORE_MIGRATED from=%s to=%s", label, folder.Old, folder.New)
				if r.Repaired() {
					line += " " + r.String()
				}
				lines = append(lines, line)
				if record {
					coreterm.Migrated("migrated to " + folder.New)
				}
				return
			}
		}
		if reason == "old_absent" {
			return
		}
		lines = append(lines, fmt.Sprintf("%s_STORE_MIGRATION_SKIPPED reason=%s", label, reason))
		if record {
			coreterm.Migrated("skipped: " + reason)
		}
	}
	recovery, e := machinepaths.RecoveryFolder()
	move("RECOVERY", recovery, e, true)
	logs, e := machinepaths.LogsFolder()
	move("LOG", logs, e, false)
	return lines
}
