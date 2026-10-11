//go:build windows && amd64

package connectioninstall

import (
	"context"
	"fmt"
	"os"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/app/usbhost"
	"time"
)

// The supervisor counter only revokes an already native-proven listener. It
// cannot supply ownership or make a missing/changed native proof acceptable.
func nativeMaintenanceGenerationGuard(guid string) (func() bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, err := netconfig.ResolveMacProofNative(ctx, guid)
	host, ready := usbhost.Proof()
	generation, present := usbhost.SharedHostSupervisorDetails().(usbhost.SupervisorSnapshot)
	if err != nil || !ready || !present || !generation.Ready || generation.Generation == 0 {
		return nil, fmt.Errorf("USB_NATIVE_REMOTE_GENERATION_UNAVAILABLE")
	}
	return func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		current, valid := usbhost.Proof()
		freshMac, err := netconfig.ResolveMacProofNative(ctx, guid)
		fresh, present := usbhost.SharedHostSupervisorDetails().(usbhost.SupervisorSnapshot)
		return valid && current == host && err == nil && freshMac == mac && present && fresh.Ready && fresh.Generation == generation.Generation
	}, nil
}

func remoteFirewallNative(enabled bool, guid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if err := netconfig.CleanupLegacyMaintenanceNative(ctx, Verify); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	if !strings.EqualFold(guid, netconfig.NativeMacGUID) {
		return fmt.Errorf("USB_NATIVE_REMOTE_MAC_SCOPE_INVALID")
	}
	executable, err := os.Executable()
	if err != nil || Verify(executable) != nil {
		return fmt.Errorf("USB_NATIVE_REMOTE_EXECUTABLE_UNVERIFIED")
	}
	mac, err := netconfig.ResolveMacProofNative(ctx, guid)
	if err != nil {
		return err
	}
	host, ready := usbhost.Proof()
	if !ready {
		return fmt.Errorf("USB_NATIVE_REMOTE_HOST_NOT_READY")
	}
	freshGeneration := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if Verify(executable) != nil {
			return fmt.Errorf("USB_NATIVE_REMOTE_EXECUTABLE_CHANGED")
		}
		current, valid := usbhost.Proof()
		freshMac, err := netconfig.ResolveMacProofNative(ctx, guid)
		if !valid || current != host || err != nil || freshMac != mac {
			return fmt.Errorf("USB_NATIVE_REMOTE_GENERATION_CHANGED")
		}
		return nil
	}
	return netconfig.VerifyMaintenanceCoverageNative(ctx, host, executable, freshGeneration)
}
