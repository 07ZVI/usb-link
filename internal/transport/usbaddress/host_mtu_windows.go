//go:build windows && amd64

package usbaddress

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

// SetHostMTU changes only the currently proved service interface. Mac callers
// first verify the physical interface MTU; a detached Mac restores 1500 for the
// native iPad path. No route, address, forwarding or firewall flag is changed.
func SetHostMTU(ctx context.Context, p InterfaceProof, mtu int) error {
	if p.Role != "host" || p.Index == 0 || p.LUID == 0 || p.Created <= 0 || !strings.EqualFold(p.GUID, HostGUID) || (mtu != 1500 && mtu != 9000 && mtu != 16000) {
		return fmt.Errorf("USB_HOST_MTU_SCOPE_INVALID")
	}
	release, err := ConfigurationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err = VerifyProofs([]InterfaceProof{p}); err != nil {
		return err
	}
	f := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if err = windows.GetIpInterfaceEntry(&f); err != nil {
		return err
	}
	if f.InterfaceIndex != p.Index || f.WeakHostSend != 1 || f.WeakHostReceive != 1 || f.ForwardingEnabled != 1 {
		return fmt.Errorf("USB_HOST_MTU_FLAGS_CHANGED")
	}
	if f.NlMtu != uint32(mtu) {
		f.SitePrefixLength = 0
		f.NlMtu = uint32(mtu)
		rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(&f)))
		if rc != 0 {
			return fmt.Errorf("USB_HOST_MTU_SET_%d", rc)
		}
	}
	if err = VerifyProofs([]InterfaceProof{p}); err != nil {
		return err
	}
	f = windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if windows.GetIpInterfaceEntry(&f) != nil || f.NlMtu != uint32(mtu) || f.InterfaceIndex != p.Index || f.WeakHostSend != 1 || f.WeakHostReceive != 1 || f.ForwardingEnabled != 1 {
		return fmt.Errorf("USB_HOST_MTU_READBACK_FAILED")
	}
	return nil
}
