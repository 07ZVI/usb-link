package usbaddress

import (
	"fmt"
	"net/netip"
)

type subnetRoute struct {
	Index   uint32
	LUID    uint64
	Prefix  netip.Prefix
	NextHop netip.Addr
}
type subnetAddress struct {
	Index  uint32
	LUID   uint64
	IP     netip.Addr
	Prefix uint8
}

func verifyUSBSubnetRows(proofs []InterfaceProof, routes []subnetRoute, addresses []subnetAddress) error {
	owned := map[uint32]uint64{}
	for _, p := range proofs {
		if p.Index == 0 || p.LUID == 0 || owned[p.Index] != 0 {
			return fmt.Errorf("invalid USB interface ownership")
		}
		owned[p.Index] = p.LUID
	}
	network := netip.MustParsePrefix("10.6.9.0/24")
	for _, r := range routes {
		if !r.Prefix.IsValid() || !r.Prefix.Addr().Is4() || !r.NextHop.Is4() {
			return fmt.Errorf("invalid native IPv4 route")
		}
		if r.Prefix.Bits() == 0 {
			continue
		}
		if !network.Contains(r.Prefix.Addr()) && !r.Prefix.Contains(network.Addr()) {
			continue
		}
		ip := r.Prefix.Addr().String()
		allowed := ip == "10.6.9.1" || ip == "10.6.9.2" || ip == "10.6.9.3" || ip == "10.6.9.253" || ip == "10.6.9.254"
		if owned[r.Index] != r.LUID || r.LUID == 0 || r.Prefix.Bits() != 32 || !allowed || !r.NextHop.IsUnspecified() {
			return fmt.Errorf("USB subnet conflicts with an existing route")
		}
	}
	for _, a := range addresses {
		if !a.IP.Is4() || a.Prefix > 32 {
			return fmt.Errorf("invalid native IPv4 address")
		}
		if !network.Contains(a.IP) {
			continue
		}
		ip := a.IP.String()
		if owned[a.Index] != a.LUID || a.LUID == 0 || a.Prefix != 32 || (ip != "10.6.9.1" && ip != "10.6.9.253" && ip != "10.6.9.254") {
			return fmt.Errorf("USB subnet conflicts with an existing address")
		}
	}
	return nil
}
