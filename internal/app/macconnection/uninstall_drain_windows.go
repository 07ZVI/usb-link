//go:build windows && amd64

package macconnection

import (
	"errors"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/transport/winusb"
	"sync/atomic"
)

// This capability is constructed only while the global bridge runtime object
// is exclusively held in this synchronous local uninstall stack. No public
// boolean can skip the ordinary per-runtime ownership check.
type uninstallRuntimeDrain struct {
	parent string
	active atomic.Bool
}

func (d *uninstallRuntimeDrain) verify(parent string) error {
	if d == nil || !d.active.Load() || !strings.EqualFold(filepath.Clean(parent), d.parent) {
		return errors.New("MAC_UNINSTALL_RUNTIME_DRAIN_UNPROVEN")
	}
	return nil
}

// WithExclusiveUninstallRecovery prevents a detached bridge in any session
// from acquiring its runtime ownership while restore-only factories run. It
// cannot stop a holder: an existing object retains the normal refusal. The
// caller separately retains the verified SCM lifecycle and recovery-file gates.
func WithExclusiveUninstallRecovery(parent string, restore func(func() error) error, finish func() error) (RecoveryReport, error) {
	var report RecoveryReport
	if restore == nil || finish == nil || !safeRuntimeDirectory(parent) {
		return report, errors.New("MAC_UNINSTALL_RUNTIME_DIRECTORY_UNPROVEN")
	}
	release, err := winusb.OwnRuntime()
	if err != nil {
		return report, errors.New("MAC_UNINSTALL_BRIDGE_NOT_DRAINED")
	}
	d := &uninstallRuntimeDrain{parent: filepath.Clean(parent)}
	d.active.Store(true)
	defer func() { d.active.Store(false); release() }()
	verify := func() error { return d.verify(parent) }
	if err := restore(verify); err != nil {
		return report, err
	}
	if err := verify(); err != nil {
		return report, err
	}
	report, err = recoverWithDrain(parent, d)
	if err != nil {
		return report, err
	}
	if err := verify(); err != nil {
		return report, err
	}
	if err := finish(); err != nil {
		return report, err
	}
	return report, verify()
}
