//go:build windows && amd64 && !usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
)

var localPhotoPublicRecoveryError error

func StartPhotoIsolation(_ context.Context, dir string) func() {
	localPhotoPublicRecoveryError = RestorePhotoIsolation(dir)
	return func() {}
}
func SetPhotoIsolationPersistence(func(bool) error, func() (bool, error)) {}
func SetPhotoIsolationMaster(bool)                                        {}
func SetPhotoIsolation(on bool, _ string) error {
	if on {
		return errors.New("PHOTO_LOCAL_BUILD_REQUIRED")
	}
	return nil
}
func PhotoIsolationDiagnostics() any {
	if localPhotoPublicRecoveryError != nil {
		return map[string]any{"available": false, "phase": "recovery_pending", "error": "PHOTO_RESTORE_FAILED"}
	}
	return nil
}
func BindPhotoIsolationTarget(Snapshot) error {
	if localPhotoPublicRecoveryError != nil {
		return errors.New("PHOTO_RECOVERY_PENDING")
	}
	return nil
}
