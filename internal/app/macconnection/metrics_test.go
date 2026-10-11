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
