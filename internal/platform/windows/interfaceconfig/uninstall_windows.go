//go:build windows && amd64

package interfaceconfig

import "errors"

// The fixed protected recovery directory comes from the local installed owner,
// never from an RPC argument. Request changes no interface; each process must
// still freshly authorize and restore only its exact obligations before delete.
func RequestPersistentUninstall(dir string) error {
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	r, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return e
	}
	r.RestoreRequested = true
	return writeConfigReceiptFile(dir, r, true)
}
func PersistentRestoreRequested(dir string) (bool, error) {
	finish, e := lockConfig()
	if e != nil {
		return false, e
	}
	defer finish()
	r, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return false, e
	}
	return r.RestoreRequested, nil
}

// The uninstall coordinator calls this only after all interfaces have completed
// typed original readback. An orphan/nonempty obligation always remains on disk.
func FinishPersistentUninstall(dir string) error {
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	r, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return e
	}
	if !r.RestoreRequested || len(r.DAD) != 0 || len(r.Persistent) != 0 {
		return errors.New("USB_INTERFACE_CONFIG_RESTORE_INCOMPLETE")
	}
	return clearConfigReceiptFile(dir, r)
}
