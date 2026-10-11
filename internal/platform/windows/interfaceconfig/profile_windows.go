//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"log"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
)

// WintunProfileOps is only for fixed host/Mac protected lifecycle owners.
// Original-value presence/absence is independently proved by Apply/Restore;
// this callback must fresh-check the protected session and native target.
func WintunProfileOps(s Scope, verifyOwner func() error, logger *log.Logger) ProfileOps {
	p := usbaddress.InterfaceProof{GUID: s.GUID, Index: s.Index, LUID: s.LUID}
	recovery := netconfig.OwnedProfileRecoveryIdentity{Role: s.Role, GUID: s.GUID, Index: s.Index, LUID: s.LUID}
	return ProfileOps{
		Read: func(ctx context.Context) (string, uint32, error) {
			return netconfig.ReadOwnedPrivateProfileForRestoreNative(ctx, recovery, verifyOwner, logger)
		},
		SetPrivateExpected: func(ctx context.Context, g string, n uint32) error {
			if e := netconfig.VerifyOwnedWintunRecoveryIdentityNative(ctx, recovery, verifyOwner); e != nil {
				return e
			}
			if e := netconfig.SetPrivateProfileWithOriginalNative(ctx, p, g, n, logger); e != nil {
				return e
			}
			return netconfig.VerifyOwnedWintunRecoveryIdentityNative(ctx, recovery, verifyOwner)
		},
		Restore: func(ctx context.Context, g string, n uint32) error {
			return netconfig.RestoreOwnedPrivateProfileNative(ctx, recovery, verifyOwner, g, n, logger)
		},
	}
}
func RestoreSecondaryForUninstall(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) error {
	requested, e := PersistentRestoreRequested(dir)
	if e != nil {
		return e
	}
	if !requested {
		return nil
	}
	if e := RestorePersistent(ctx, dir, s, verifyOwner, profile); e != nil {
		return e
	}
	return RestoreDADZero(ctx, dir, s, verifyOwner)
}
