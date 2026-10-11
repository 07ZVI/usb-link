//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LaunchPrepared switches manual setup to its exact, receipt-verified copy.
// No caller-supplied arguments, shell, or network command is accepted. Remote
// updates already run the installed copy and keep their authorized job context.
func LaunchPrepared(installed string, release func() error) (bool, error) {
	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	if err = Verify(installed); err != nil {
		return false, err
	}
	if strings.EqualFold(self, installed) {
		return false, Verify(self)
	}
	source, err := fileHash(self)
	if err != nil {
		return false, err
	}
	receipt, err := readReceipt(filepath.Dir(installed))
	if err != nil || source != receipt.SHA {
		return false, fmt.Errorf("installed launch copy differs from setup")
	}
	if err = release(); err != nil {
		return false, err
	}
	// Starting before releasing the recovery lock would make the new process
	// mistake its installer for another running connection manager.
	c := exec.Command(installed, PreparedInstallArgument)
	if err = c.Start(); err != nil {
		return false, err
	}
	_ = c.Process.Release()
	return true, nil
}
