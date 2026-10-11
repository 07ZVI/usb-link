package usbaddress

import (
	"net/netip"
	"testing"
)

func TestNativeSubnetRowsRejectForeignAndBroadOverlap(t *testing.T) {
	proofs := []InterfaceProof{{Index: 7, LUID: 70}, {Index: 8, LUID: 80}}
	route := subnetRoute{7, 70, netip.MustParsePrefix("10.6.9.3/32"), netip.IPv4Unspecified()}
	address := subnetAddress{8, 80, netip.MustParseAddr("10.6.9.1"), 32}
	if e := verifyUSBSubnetRows(proofs, []subnetRoute{route}, []subnetAddress{address}); e != nil {
		t.Fatal(e)
	}
	for _, r := range []subnetRoute{
		{9, 90, route.Prefix, route.NextHop},
		{7, 71, route.Prefix, route.NextHop},
		{7, 70, netip.MustParsePrefix("10.6.9.0/24"), route.NextHop},
		{7, 70, netip.MustParsePrefix("10.0.0.0/8"), route.NextHop},
		{7, 70, netip.MustParsePrefix("10.6.9.9/32"), route.NextHop},
		{7, 70, route.Prefix, netip.MustParseAddr("10.6.9.1")},
	} {
		if verifyUSBSubnetRows(proofs, []subnetRoute{r}, nil) == nil {
			t.Fatal("conflicting route accepted", r)
		}
	}
	for _, a := range []subnetAddress{
		{9, 90, address.IP, 32}, {8, 81, address.IP, 32}, {8, 80, address.IP, 24}, {8, 80, netip.MustParseAddr("10.6.9.3"), 32},
	} {
		if verifyUSBSubnetRows(proofs, nil, []subnetAddress{a}) == nil {
			t.Fatal("conflicting address accepted", a)
		}
	}
	if e := verifyUSBSubnetRows(proofs, []subnetRoute{{9, 90, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("192.168.1.1")}, {9, 90, netip.MustParsePrefix("192.168.1.0/24"), netip.IPv4Unspecified()}}, nil); e != nil {
		t.Fatal("unrelated LAN or default route blocked", e)
	}
}
