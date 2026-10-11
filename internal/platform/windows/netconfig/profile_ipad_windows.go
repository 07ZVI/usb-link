//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"log"
	"suhang/usbnet/internal/platform/windows/wincom"
	"suhang/usbnet/internal/transport/usbaddress"
)

// This mandatory owner callback freshly proves the protected application
// original plus exact UsbNcm native instance/root/consent and mapping. NLM
// output is observation only; it never supplies an ordinary firewall proof.
func ownedIPadProfileVerifier(ctx context.Context, p usbaddress.InterfaceProof, verifyOwnedIPad func() error) func() error {
	return func() error {
		if ctx == nil || p.Role != "ipad" || p.AddressMode != "" || verifyOwnedIPad == nil {
			return errors.New("USB_NATIVE_IPAD_PROFILE_OWNER_REQUIRED")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := verifyOwnedIPad(); e != nil {
			return errors.New("USB_NATIVE_IPAD_PROFILE_OWNER_UNPROVEN")
		}
		if _, e := nativeRuleInterface(ctx, p); e != nil {
			return e
		}
		if e := verifyOwnedIPad(); e != nil {
			return errors.New("USB_NATIVE_IPAD_PROFILE_OWNER_UNPROVEN")
		}
		return ctx.Err()
	}
}

func ReadOwnedIPadPrivateProfileNative(ctx context.Context, p usbaddress.InterfaceProof, verifyOwnedIPad func() error, logger *log.Logger) (guid string, category uint32, err error) {
	verify := ownedIPadProfileVerifier(ctx, p, verifyOwnedIPad)
	err = nativeStep(logger, "private_profile_recovery_read", func() error {
		return wincom.WithApartment(func() error {
			n, g, c, e := nlmReadVerified(ctx, p.GUID, verify)
			defer nlmRelease(n)
			guid, category = g, c
			return e
		})
	})
	return
}

func SetOwnedIPadPrivateProfileWithOriginalNative(ctx context.Context, p usbaddress.InterfaceProof, verifyOwnedIPad func() error, expectedNetworkGUID string, originalCategory uint32, logger *log.Logger) error {
	if !guidPattern.MatchString(expectedNetworkGUID) || originalCategory > 1 {
		return errors.New("USB_NATIVE_PROFILE_ORIGINAL_INVALID")
	}
	return applyPrivateProfileVerified(ctx, p.GUID, ownedIPadProfileVerifier(ctx, p, verifyOwnedIPad), expectedNetworkGUID, 1, &originalCategory, false, logger)
}

func RestoreOwnedIPadPrivateProfileNative(ctx context.Context, p usbaddress.InterfaceProof, verifyOwnedIPad func() error, expectedNetworkGUID string, originalCategory uint32, logger *log.Logger) error {
	if !guidPattern.MatchString(expectedNetworkGUID) || originalCategory > 1 {
		return errors.New("USB_NATIVE_PROFILE_ORIGINAL_INVALID")
	}
	owned := uint32(1)
	return applyPrivateProfileVerified(ctx, p.GUID, ownedIPadProfileVerifier(ctx, p, verifyOwnedIPad), expectedNetworkGUID, originalCategory, &owned, true, logger)
}
