//go:build usblink_local_remote

package connectioninstall

import (
	"fmt"
	"os"
)

// The caller holds the local install mutex and proves a terminal journal and
// transaction. Operations address that journal's exact directory only.
type localInstallCleanupOps struct {
	validateDirectory func() error
	entries           func() ([]string, error)
	verifyPackage     func() error
	removePackage     func() error
	removeDirectory   func() error
}

func cleanupLocalInstallDirectory(op localInstallCleanupOps) error {
	if err := op.validateDirectory(); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	names, err := op.entries()
	if err != nil {
		return err
	}
	if len(names) > 1 || len(names) == 1 && names[0] != "setup.exe" {
		return fmt.Errorf("LOCAL_REMOTE_STAGED_DIRECTORY_NOT_EMPTY")
	}
	if len(names) == 1 {
		if err = op.verifyPackage(); err != nil {
			return err
		}
		if err = op.validateDirectory(); err != nil {
			return err
		}
		if err = op.removePackage(); err != nil {
			return err
		}
	}
	// A prior attempt may already have removed setup.exe before directory removal
	// failed (for example while an older UI still used it as its working directory).
	if err = op.validateDirectory(); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err = op.removeDirectory(); err != nil {
		return err
	}
	if err = op.validateDirectory(); os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("LOCAL_REMOTE_STAGED_DIRECTORY_REMAINS")
}

func localInstallCleanupProcessSafe(pid uint32, creation uint64, exited func(uint32, uint64) (bool, bool)) bool {
	if pid == 0 && creation == 0 {
		return true
	}
	if pid == 0 || creation == 0 {
		return false
	}
	dead, known := exited(pid, creation)
	return dead && known
}
