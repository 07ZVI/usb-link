//go:build windows && amd64

package bridgeworker

import (
	"fmt"
	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/transport/usbaddress"
	"unsafe"
)

// Only the successful current factory/address phase can call this checkpoint.
// The persistent package independently repeats the complete native/Store proof.
func macOwnedAddressCreated(p usbaddress.InterfaceProof) (int64, error) {
	row := windows.MibUnicastIpAddressRow{InterfaceLuid: p.LUID, InterfaceIndex: p.Index}
	a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
	a.Family = windows.AF_INET
	a.Addr = [4]byte{10, 6, 9, 253}
	if windows.GetUnicastIpAddressEntry(&row) != nil || row.InterfaceLuid != p.LUID || row.InterfaceIndex != p.Index || row.OnLinkPrefixLength != 32 || row.PrefixOrigin != 1 || row.SuffixOrigin != 1 || row.DadState != 4 || row.SkipAsSource != 1 {
		return 0, fmt.Errorf("USB_MAC_PERSISTENT_ADDRESS_CHECKPOINT_UNPROVEN")
	}
	created := int64(uint64(row.CreationTimeStamp.HighDateTime)<<32 | uint64(row.CreationTimeStamp.LowDateTime))
	if created <= 0 {
		return 0, fmt.Errorf("USB_MAC_PERSISTENT_CREATED_UNPROVEN")
	}
	return created, nil
}
