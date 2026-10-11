//go:build windows && amd64

package netconfig

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestVerifiedMacMTURowPreservesUnrelatedPolicy(t *testing.T) {
	before := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: 5, InterfaceLuid: 9, NlMtu: 1500, SitePrefixLength: 32, Metric: 5000, UseAutomaticMetric: 1, ForwardingEnabled: 1, WeakHostSend: 1, WeakHostReceive: 1, DisableDefaultRoutes: 1, DadTransmits: 2, RetransmitTime: 700, ZoneIndices: [windows.ScopeLevelCount]uint32{5, 7}}
	row, err := prepareVerifiedMacMTURow(before, 5, 9, 16000)
	if err != nil {
		t.Fatal(err)
	}
	if row.NlMtu != 16000 || row.SitePrefixLength != 0 {
		t.Fatal("MTU/prefix normalization missing")
	}
	row.NlMtu = before.NlMtu
	row.SitePrefixLength = before.SitePrefixLength
	if row != before {
		t.Fatal("native MTU plan changed unrelated fields")
	}
	for _, original := range []windows.MibIpInterfaceRow{{Family: windows.AF_INET6, InterfaceIndex: 5, InterfaceLuid: 9}, {Family: windows.AF_INET, InterfaceIndex: 6, InterfaceLuid: 9}, {Family: windows.AF_INET, InterfaceIndex: 5, InterfaceLuid: 10}} {
		if _, err := prepareVerifiedMacMTURow(original, 5, 9, 16000); err == nil {
			t.Fatal("accepted changed row scope")
		}
	}
}
