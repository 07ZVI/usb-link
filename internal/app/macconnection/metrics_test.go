package macconnection

import (
	"strings"
	"testing"
)

func TestBridgeStatsUseDirectionalBytesAndRejectMalformed(t *testing.T) {
	in, out, drops, ok := parseCounters("2026/10/02 STATS {USBReads:8 ToMac:9 ToWindowsBytes:123 ToMacBytes:456 Dropped:7 Filtered:6} peer=00:01:02:03:04:05")
	if !ok || in != 123 || out != 456 || drops != 7 {
		t.Fatal("counter mapping", in, out, drops, ok)
	}
	for _, bad := range []string{"ToMacBytes:1", "ToMacBytes:1 ToWindowsBytes:2 Dropped:3 Dropped:4", "ToMacBytes:-1 ToWindowsBytes:2 Dropped:3", "ToMacBytes:18446744073709551616 ToWindowsBytes:2 Dropped:3", strings.Repeat("x", 4097)} {
		if _, _, _, ok := parseCounters(bad); ok {
			t.Fatal("malformed counter line accepted")
		}
	}
}

func TestDescriptorSummaryLineIsFixedNumericTextOnly(t *testing.T) {
	good := "2026/10/19 USB_MAC_NCM_DESCRIPTOR_SUMMARY device{vid=05ac pid=1903 bcdDevice=0x0510} iad{present=no} data{pipes_alt1=0x81:bulk:max1024:iv0 bulk_in=yes}"
	got, ok := parseDescriptorSummary(good)
	if !ok || !strings.HasPrefix(got, "device{vid=05ac") || strings.Contains(got, "USB_MAC") {
		t.Fatal("summary rejected or prefix retained", got, ok)
	}
	for _, bad := range []string{
		"no marker", "USB_MAC_NCM_DESCRIPTOR_SUMMARY ", "USB_MAC_NCM_DESCRIPTOR_SUMMARY serial=ABC\u0000",
		"USB_MAC_NCM_DESCRIPTOR_SUMMARY a;b", "USB_MAC_NCM_DESCRIPTOR_SUMMARY \"quoted\"",
		"USB_MAC_NCM_DESCRIPTOR_SUMMARY " + strings.Repeat("a", 2049), strings.Repeat("x", 4097),
	} {
		if _, ok := parseDescriptorSummary(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}
