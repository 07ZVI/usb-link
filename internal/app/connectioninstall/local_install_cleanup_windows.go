//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/app/remoteupdate"
)

// Called only with localInstallMutex held. Unknown process identity or an
// unfinished transaction cannot release bytes even if the job says terminal.
func cleanupLocalInstallTerminal(root string, j localInstallJob) error {
	if !localInstallIDValid(j.ID) || !localInstallTerminal(j.Status) {
		return fmt.Errorf("LOCAL_REMOTE_JOB_PENDING")
	}
	t, present, err := readInstallationTransaction()
	if err != nil || present && t.Phase != InstallComplete && t.Phase != InstallRolledBack {
		return fmt.Errorf("LOCAL_REMOTE_INSTALL_RECOVERY_REQUIRED")
	}
	if j.Status == "complete" && (j.InstallerPID == 0 || j.InstallerCreation == 0) {
		return fmt.Errorf("LOCAL_REMOTE_CLEANUP_PROCESS_UNPROVEN")
	}
	for _, process := range []struct {
		pid      uint32
		creation uint64
	}{{j.BrokerPID, j.BrokerCreation}, {j.DispatcherPID, j.DispatcherCreation}, {j.InstallerPID, j.InstallerCreation}} {
		if !localInstallCleanupProcessSafe(process.pid, process.creation, localInstallProcessExited) {
			return fmt.Errorf("LOCAL_REMOTE_CLEANUP_PROCESS_UNPROVEN")
		}
	}
	if _, err = coreProtectedRead(root, true, false); err != nil {
		return err
	}
	p := localInstallPath(root, j.ID)
	dir := filepath.Dir(p)
	return cleanupLocalInstallDirectory(localInstallCleanupOps{
		validateDirectory: func() error { _, e := coreProtectedRead(dir, true, false); return e },
		entries: func() ([]string, error) {
			entries, e := os.ReadDir(dir)
			if e != nil {
				return nil, e
			}
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			return names, nil
		},
		verifyPackage: func() error {
			if _, e := coreProtectedRead(p, false, false); e != nil {
				return e
			}
			f, e := os.Open(p)
			if e != nil {
				return e
			}
			defer f.Close()
			return remoteupdate.VerifyBinary(f, j.Manifest)
		},
		removePackage:   func() error { return os.Remove(p) },
		removeDirectory: func() error { return os.Remove(dir) },
	})
}
