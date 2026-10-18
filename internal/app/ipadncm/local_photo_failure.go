package ipadncm

import "errors"

type localPhotoFailure struct {
	code, kind string
	native     uint32
	cause      error
}

func (e *localPhotoFailure) Error() string { return e.code }
func (e *localPhotoFailure) Unwrap() error { return e.cause }
func photoFailure(code string, cause error) error {
	return &localPhotoFailure{code: code, cause: cause}
}
func photoNativeFailure(code, kind string, native uint32, cause error) error {
	return &localPhotoFailure{code: code, kind: kind, native: native, cause: cause}
}
func photoKnownCode(s string) bool {
	switch s {
	case "PHOTO_DEBUG_REQUIRED", "PHOTO_DISABLE_CANCELLED_OR_CHANGED", "PHOTO_DISABLE_FAILED", "PHOTO_DISABLE_UNCONFIRMED", "PHOTO_ENABLE_UNCONFIRMED", "PHOTO_JOURNAL_CHECKPOINT_FAILED", "PHOTO_JOURNAL_INVALID", "PHOTO_JOURNAL_LIMIT", "PHOTO_JOURNAL_OWNERSHIP_CHANGED", "PHOTO_JOURNAL_READBACK_FAILED", "PHOTO_JOURNAL_SAVE_FAILED", "PHOTO_JOURNAL_UNREADABLE", "PHOTO_KNOWN_IDENTITY_MISMATCH", "PHOTO_KNOWN_SAVE_FAILED", "PHOTO_KNOWN_UNPROVEN", "PHOTO_KNOWN_UNREADABLE", "PHOTO_LOCAL_BUILD_REQUIRED", "PHOTO_LOCAL_DIAGNOSTICS_REQUIRED", "PHOTO_NATIVE_DISABLE_FAILED", "PHOTO_NATIVE_ENABLE_FAILED", "PHOTO_NATIVE_OWNERSHIP_UNPROVEN", "PHOTO_NATIVE_STATE_UNPROVEN", "PHOTO_NOT_STARTED", "PHOTO_ORIGINAL_CHANGED", "PHOTO_ORIGINAL_UNPROVEN", "PHOTO_PHANTOM_UNPROVEN", "PHOTO_PREFERENCE_FAILED", "PHOTO_PREFERENCE_UNAVAILABLE", "PHOTO_PROPERTY_CHANGED", "PHOTO_PROPERTY_RESTORE_FAILED", "PHOTO_RECEIPT_INVALID", "PHOTO_RECOVERY_PENDING", "PHOTO_REQUEST_INVALID", "PHOTO_RESTORE_FAILED", "PHOTO_RESTORE_STATE_CHANGED", "PHOTO_RESTORE_TARGET_CHANGED", "PHOTO_RESTORE_UNCONFIRMED", "PHOTO_ROOT_AMBIGUOUS", "PHOTO_ROOT_UNPROVEN", "PHOTO_SCAN_UNPROVEN", "PHOTO_STATE_UNPROVEN", "PHOTO_STORE_CHANGED", "PHOTO_STORE_UNPROVEN", "PHOTO_TARGET_CHANGED", "PHOTO_TARGET_UNPROVEN":
		return true
	}
	return false
}
func photoFailureDetails(err error) (code, kind string, native uint32) {
	for i := 0; i < 16 && err != nil; i++ {
		if photoKnownCode(err.Error()) {
			code = err.Error()
		}
		if e, ok := err.(*localPhotoFailure); ok && (e.kind == "CONFIGRET" || e.kind == "WIN32") {
			kind, native = e.kind, e.native
		}
		err = errors.Unwrap(err)
	}
	return
}
