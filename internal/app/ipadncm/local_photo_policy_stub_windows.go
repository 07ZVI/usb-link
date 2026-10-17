//go:build windows && amd64 && !usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
)

var localPhotoPolicyPublicError error

func StartLocalPhotoPolicy(_ context.Context, dir string) func() {
	localPhotoPolicyPublicError = RestoreLocalPhotoPolicy(dir)
	return func() {}
}
func SetLocalPhotoPolicyPersistence(func(bool) error, func() (bool, error)) {}
func SetLocalPhotoPolicyMaster(bool)                                        {}
func SetLocalPhotoPolicy(on bool, _ string) error {
	if on {
		return errors.New("PHOTO_POLICY_LOCAL_BUILD_REQUIRED")
	}
	return nil
}
func LocalPhotoPolicyDiagnostics() any { return defaultPhotoPolicyDiagnostics() }
func BindLocalPhotoPolicyTarget(Snapshot) error {
	if localPhotoPolicyPublicError != nil {
		return errors.New("PHOTO_POLICY_RECOVERY_PENDING")
	}
	return nil
}
func LocalPhotoPolicyBlocksRuntimeIsolation() bool { return localPhotoPolicyPublicError != nil }
