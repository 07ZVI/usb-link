//go:build windows && amd64

package usbaddress

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

// NativeDetails queries only the protected, bounded ownership snapshot. It
// exposes no device identifiers, unrelated adapters, payload or pairing data.
func NativeDetails(proofs []InterfaceProof) any {
	out := []map[string]any{}
	if len(proofs) > 4 {
		return map[string]any{"error": "USB_TOPOLOGY_TOO_LARGE"}
	}
	for _, p := range proofs {
		d := map[string]any{"index": p.Index, "role": p.Role}
		r := windows.MibIfRow2{InterfaceLuid: p.LUID}
		if p.LUID == 0 || p.Index == 0 || windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r) != nil || r.InterfaceIndex != p.Index || !strings.EqualFold(r.InterfaceGuid.String(), p.GUID) {
			d["error"] = "USB_INTERFACE_IDENTITY_CHANGED"
			out = append(out, d)
			continue
		}
		d["link_mtu"] = r.Mtu
		d["peer_paths"] = nativePeerPaths(p)
		f := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
		if e := windows.GetIpInterfaceEntry(&f); e != nil {
			d["flags_error"] = e.Error()
		} else {
			d["weak_send"] = f.WeakHostSend != 0
			d["weak_receive"] = f.WeakHostReceive != 0
			d["forwarding"] = f.ForwardingEnabled != 0
			d["mtu"] = f.NlMtu
		}
		addresses := []map[string]any{}
		for _, ip := range [][4]byte{{10, 6, 9, 1}, {10, 6, 9, 253}, {10, 6, 9, 254}} {
			a := windows.MibUnicastIpAddressRow{InterfaceLuid: p.LUID, InterfaceIndex: p.Index}
			v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&a.Address))
			v.Family = windows.AF_INET
			v.Addr = ip
			if windows.GetUnicastIpAddressEntry(&a) == nil {
				addresses = append(addresses, map[string]any{"ip": fmt.Sprintf("10.6.9.%d", ip[3]), "prefix": a.OnLinkPrefixLength, "dad": a.DadState, "skip_source": a.SkipAsSource != 0})
			}
		}
		d["addresses"] = addresses
		routes := []map[string]any{}
		for _, peer := range []byte{1, 2, 3} {
			route := windows.MibIpForwardRow2{InterfaceLuid: p.LUID, InterfaceIndex: p.Index}
			route.DestinationPrefix.PrefixLength = 32
			dest := (*windows.RawSockaddrInet4)(unsafe.Pointer(&route.DestinationPrefix.Prefix))
			dest.Family = windows.AF_INET
			dest.Addr = [4]byte{10, 6, 9, peer}
			next := (*windows.RawSockaddrInet4)(unsafe.Pointer(&route.NextHop))
			next.Family = windows.AF_INET
			if windows.GetIpForwardEntry2(&route) == nil {
				routes = append(routes, map[string]any{"destination": fmt.Sprintf("10.6.9.%d/32", peer), "metric": route.Metric, "on_link": next.Addr == [4]byte{}})
			}
		}
		d["routes"] = routes
		out = append(out, d)
	}
	return out
}
