//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"unsafe"
)

const NativeMacGUID = "{A4611646-E050-4D25-B83E-633A5598F302}"

func nativeMacScope(ctx context.Context, p usbaddress.InterfaceProof) error {
	if ctx == nil || !strings.EqualFold(p.GUID, NativeMacGUID) || p.Role != "" || p.Index == 0 || p.LUID == 0 {
		return errors.New("USB_NATIVE_MAC_SCOPE_INVALID")
	}
	return verifyNativeMacMTUIdentity(ctx, p.Index, p.GUID, p.LUID)
}

func nativeRuleInterface(ctx context.Context, p usbaddress.InterfaceProof) (string, error) {
	if ctx == nil || p.Index == 0 || p.LUID == 0 || !guidPattern.MatchString(p.GUID) {
		return "", errors.New("USB_NATIVE_FIREWALL_INTERFACE_INVALID")
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if e := usbaddress.VerifyProofs([]usbaddress.InterfaceProof{p}); e != nil {
		return "", e
	}
	r := windows.MibIfRow2{InterfaceLuid: p.LUID}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r) != nil || r.InterfaceIndex != p.Index || !strings.EqualFold(r.InterfaceGuid.String(), p.GUID) {
		return "", errors.New("USB_NATIVE_FIREWALL_INTERFACE_CHANGED")
	}
	alias := windows.UTF16ToString(r.Alias[:])
	if alias == "" || len(alias) > 128 {
		return "", errors.New("USB_NATIVE_FIREWALL_ALIAS_INVALID")
	}
	return alias, nil
}
func ResolveMacProofNative(ctx context.Context, guid string) (usbaddress.InterfaceProof, error) {
	p := usbaddress.InterfaceProof{GUID: guid}
	if !strings.EqualFold(guid, NativeMacGUID) {
		return p, errors.New("USB_NATIVE_MAC_SCOPE_INVALID")
	}
	g, _ := windows.GUIDFromString(guid)
	proc := macMTUGuidToLuid
	if proc.Find() != nil {
		return p, errors.New("USB_NATIVE_MAC_MAPPING_UNAVAILABLE")
	}
	rc, _, _ := proc.Call(uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&p.LUID)))
	if rc != 0 || p.LUID == 0 {
		return p, errors.New("USB_NATIVE_MAC_MAPPING_UNAVAILABLE")
	}
	r := windows.MibIfRow2{InterfaceLuid: p.LUID}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r) != nil {
		return p, errors.New("USB_NATIVE_MAC_MAPPING_UNAVAILABLE")
	}
	p.Index = r.InterfaceIndex
	return p, nativeMacScope(ctx, p)
}
