//go:build windows && amd64

package interfaceconfig

import (
	"errors"
)

// ReadPersistentOriginalSnapshot reads one fixed role from the protected
// original store. It does not mutate, initialize a choice, authorize an
// interface, refresh a mapping or promote a Created stamp. Callers must hold
// their own configuration lease and independently prove native ownership.
func ReadPersistentOriginalSnapshot(dir, role string) (PersistentOriginalSnapshot, bool, error) {
	return readPersistentOriginalSnapshot(dir, role, false)
}

// ReadPersistentOriginalSnapshotForRestore is a read-only original observation
// available only behind the durable uninstall intent. It cannot authorize new
// Create/reuse or consume originals.
func ReadPersistentOriginalSnapshotForRestore(dir, role string) (PersistentOriginalSnapshot, bool, error) {
	return readPersistentOriginalSnapshot(dir, role, true)
}
func readPersistentOriginalSnapshot(dir, role string, restore bool) (PersistentOriginalSnapshot, bool, error) {
	if role != "host" && role != "mac" {
		return PersistentOriginalSnapshot{}, false, errors.New("USB_PERSISTENT_SNAPSHOT_ROLE_INVALID")
	}
	finish, e := lockConfig()
	if e != nil {
		return PersistentOriginalSnapshot{}, false, e
	}
	defer finish()
	store, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return PersistentOriginalSnapshot{}, false, e
	}
	if store.RestoreRequested != restore {
		return PersistentOriginalSnapshot{}, false, errors.New("USB_PERSISTENT_RESTORE_REQUESTED")
	}
	for _, v := range store.Persistent {
		if v.Scope.Role == role {
			s, ok := originalSnapshot(v)
			if !ok {
				return PersistentOriginalSnapshot{}, false, errors.New("USB_PERSISTENT_ORIGINAL_INCOMPLETE")
			}
			return s, true, nil
		}
	}
	return PersistentOriginalSnapshot{}, false, nil
}

// ReadDADOriginalScope exposes the exact saved local original, not a fresh
// mapping. A factory caller must independently bind its saved LUID to its
// protected source transaction and actual returned handle before restoration.
func ReadDADOriginalScope(dir, role string) (Scope, bool, error) {
	return readDADOriginalScope(dir, role, false)
}
func ReadDADOriginalScopeForRestore(dir, role string) (Scope, bool, error) {
	return readDADOriginalScope(dir, role, true)
}
func readDADOriginalScope(dir, role string, restore bool) (Scope, bool, error) {
	if role != "host" && role != "mac" {
		return Scope{}, false, errors.New("USB_DAD_SNAPSHOT_ROLE_INVALID")
	}
	finish, e := lockConfig()
	if e != nil {
		return Scope{}, false, e
	}
	defer finish()
	r, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return Scope{}, false, e
	}
	if r.RestoreRequested != restore {
		return Scope{}, false, errors.New("USB_PERSISTENT_RESTORE_REQUESTED")
	}
	for _, v := range r.DAD {
		if v.Scope.Role == role {
			return v.Scope, true, nil
		}
	}
	return Scope{}, false, nil
}

// WithHostOriginalsRestored closes only the fixed host's final protected
// uninstall checkpoint. The callback must prove its own restoring phase and
// exact native absence and must not re-enter this package.
func WithHostOriginalsRestored(dir string, commit func() error) error {
	if commit == nil {
		return errors.New("USB_HOST_RESTORE_CHECKPOINT_INVALID")
	}
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	originalAbsent := func() error {
		r, found, e := readConfigReceiptFile(dir)
		if e != nil || !found || !r.RestoreRequested {
			return errors.New("USB_HOST_RESTORE_INTENT_UNPROVEN")
		}
		return hostOriginalsRestored(r)
	}
	if e = originalAbsent(); e != nil {
		return e
	}
	if e = commit(); e != nil {
		return e
	}
	return originalAbsent()
}
