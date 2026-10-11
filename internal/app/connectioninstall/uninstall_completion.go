package connectioninstall

import "errors"

// The restore callback includes complete native/receipt absence and original
// readback. Deleting a stopped service is a separate final mutation and cannot
// run after a failed restoration or a changed owner. No missing step is inferred.
func finishVerifiedUninstall(verify, restore, remove func() error) error {
	if verify == nil || restore == nil || remove == nil {
		return errors.New("CORE_UNINSTALL_COMPLETION_INVALID")
	}
	if err := verify(); err != nil {
		return err
	}
	if err := restore(); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	return remove()
}
