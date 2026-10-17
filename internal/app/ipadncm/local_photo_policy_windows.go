//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
)

func StartLocalPhotoPolicy(_ context.Context, dir string) func() {
	_ = RestoreLocalPhotoPolicy(dir)
	return func() { _ = RestoreLocalPhotoPolicy(dir) }
}
func SetLocalPhotoPolicyPersistence(func(bool) error, func() (bool, error)) {}
func SetLocalPhotoPolicyMaster(bool)                                        {}
func SetLocalPhotoPolicy(bool, string) error {
	return errors.New("PHOTO_POLICY_RETIRED_RUNTIME_ISOLATION")
}
func LocalPhotoPolicyDiagnostics() any             { return defaultPhotoPolicyDiagnostics() }
func LocalPhotoPolicyBlocksRuntimeIsolation() bool { return !defaultIsolationReady.Load() }
func BindLocalPhotoPolicyTarget(Snapshot) error    { return defaultIsolationAdmission() }
