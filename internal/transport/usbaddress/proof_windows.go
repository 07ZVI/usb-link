//go:build windows && amd64

package usbaddress

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

func VerifyProofs(proofs []InterfaceProof) error {
	for _, p := range proofs {
		r := windows.MibIfRow2{InterfaceLuid: p.LUID}
		if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r) != nil || r.InterfaceIndex != p.Index {
			return fmt.Errorf("USB_INTERFACE_PROOF_CHANGED")
		}
		if p.Role == "host" {
			if r.Type != 53 || p.Created <= 0 || !strings.EqualFold(p.GUID, HostGUID) || !strings.EqualFold(r.InterfaceGuid.String(), HostGUID) || windows.UTF16ToString(r.Alias[:]) != HostName {
				return fmt.Errorf("USB_HOST_PROOF_INVALID")
			}
			a := windows.MibUnicastIpAddressRow{InterfaceLuid: p.LUID, InterfaceIndex: p.Index}
			v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&a.Address))
			v.Family = windows.AF_INET
			v.Addr = [4]byte{10, 6, 9, 1}
			if windows.GetUnicastIpAddressEntry(&a) != nil || a.DadState != 4 || a.OnLinkPrefixLength != 32 || a.PrefixOrigin != 1 || a.SuffixOrigin != 1 || !validHostLifetimes(p.AddressMode, a.ValidLifetime, a.PreferredLifetime) || (p.AddressMode == "persistent" && a.SkipAsSource != 0) || int64(uint64(a.CreationTimeStamp.HighDateTime)<<32|uint64(a.CreationTimeStamp.LowDateTime)) != p.Created {
				return fmt.Errorf("USB_HOST_ADDRESS_PROOF_CHANGED")
			}
		} else if p.AddressMode != "" || !strings.EqualFold(r.InterfaceGuid.String(), p.GUID) {
			return fmt.Errorf("USB_INTERFACE_GUID_CHANGED")
		}
	}
	return nil
}
