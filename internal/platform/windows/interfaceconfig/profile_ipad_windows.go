//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"log"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
)

// IPadProfileOps requires a current exact native UsbNcm/root/consent verifier;
// for restoration it instead proves the protected original and same installed
// instance. Caller cannot use an empty role or a diagnostic to grant permission.
func IPadProfileOps(s Scope, verifyOwnedIPad func() error, logger *log.Logger) ProfileOps {
	p := usbaddress.InterfaceProof{Role: s.Role, GUID: s.GUID, Index: s.Index, LUID: s.LUID}
	return ProfileOps{
		Read: func(ctx context.Context) (string, uint32, error) {
			return netconfig.ReadOwnedIPadPrivateProfileNative(ctx, p, verifyOwnedIPad, logger)
		},
		SetPrivateExpected: func(ctx context.Context, guid string, original uint32) error {
			return netconfig.SetOwnedIPadPrivateProfileWithOriginalNative(ctx, p, verifyOwnedIPad, guid, original, logger)
		},
		Restore: func(ctx context.Context, guid string, original uint32) error {
			return netconfig.RestoreOwnedIPadPrivateProfileNative(ctx, p, verifyOwnedIPad, guid, original, logger)
		},
	}
}
