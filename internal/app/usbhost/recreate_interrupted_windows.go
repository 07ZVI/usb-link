//go:build windows && amd64

package usbhost

import (
	"fmt"
	"path/filepath"
)

// RecoverInterruptedRecreate checks only an existing protected attempt/mapped
// transaction. The caller must hold the topology configuration lock and verify
// the installed source. Call early in startup to observe an actual counter
// reset; elapsed time never proves a reboot. It does not run ordinary Recover,
// create/remove an adapter, change the old journal, or settle other phases.
// attempted records selection for checking, not successful recovery.
func RecoverInterruptedRecreate(dir string) (attempted bool, err error) {
	if !hostOperationMu.TryLock() {
		return false, fmt.Errorf("USB_HOST_OPERATION_BUSY")
	}
	defer hostOperationMu.Unlock()
	t, found, err := readRecreateTransactionFile(dir)
	if err != nil {
		return false, err
	}
	path := filepath.Join(dir, "usb-host-address.json")
	return settleInterruptedRecreate(t, found, func() ([]byte, error) {
		live.Lock()
		active := live.p != (journal{})
		live.Unlock()
		if active {
			return nil, fmt.Errorf("USB_HOST_RECREATE_LIVE_HOST_PRESENT")
		}
		_, removal, e := readRemovalIntentFile(dir)
		if e != nil {
			return nil, e
		}
		if removal {
			return nil, fmt.Errorf("USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL")
		}
		_, factory, e := readPersistentFactory(dir)
		if e != nil {
			return nil, e
		}
		if factory {
			return nil, fmt.Errorf("USB_HOST_FACTORY_LEGACY_INTENT_CONFLICT")
		}
		return readRecreateJournal(dir, path)
	}, func(selected recreateTransaction, old []byte) error {
		return finishRecreateTransaction(dir, path, selected, old, false)
	})
}
