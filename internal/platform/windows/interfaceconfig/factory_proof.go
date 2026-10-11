package interfaceconfig

import (
	"errors"
	"strings"
)

// Called under the single protected configuration mutex. A post-commit error
// is propagated rather than turning a partially checkpointed transaction Ready.
func runFactoryProofCheckpoint(s Scope, sha, mode string, created int64, original func() error, proof func() (ActiveOwnership, error), fresh func() error, commit func(ActiveOwnership) error) error {
	if e := original(); e != nil {
		return e
	}
	first, e := proof()
	if e != nil {
		return e
	}
	last, e := proof()
	if e != nil {
		return e
	}
	if first != last || last.Scope != s || last.Created <= 0 || last.AddressMode != mode || (created != 0 && last.Created != created) || last.ReceiptSHA256 != sha {
		return errors.New("USB_PERSISTENT_FACTORY_ACTIVE_CHANGED")
	}
	if e = original(); e != nil {
		return e
	}
	if e = fresh(); e != nil {
		return e
	}
	if e = commit(last); e != nil {
		return e
	}
	if e = fresh(); e != nil {
		return e
	}
	return original()
}

func hostOriginalsRestored(r configReceipt) error {
	if !r.RestoreRequested {
		return errors.New("USB_HOST_RESTORE_INTENT_UNPROVEN")
	}
	for _, v := range r.Persistent {
		if v.Scope.Role == "host" || strings.EqualFold(v.Scope.GUID, HostGUID) {
			return errors.New("USB_HOST_PERSISTENT_ORIGINALS_PENDING")
		}
	}
	for _, v := range r.DAD {
		if v.Scope.Role == "host" || strings.EqualFold(v.Scope.GUID, HostGUID) {
			return errors.New("USB_HOST_DAD_ORIGINALS_PENDING")
		}
	}
	return nil
}
