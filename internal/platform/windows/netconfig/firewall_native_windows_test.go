//go:build windows && amd64

package netconfig

import (
	"reflect"
	"strings"
	"testing"

	"suhang/usbnet/internal/platform/windows/wincom"
	"suhang/usbnet/internal/transport/usbaddress"
)

// These pure fixtures do not call COM or mutate Windows. They exercise the
// typed constraint proof used before a new native firewall rule is enabled.
func TestNativeFirewallConstraintUnknowns(t *testing.T) {
	for _, tc := range []struct {
		field string
		value wincom.Value
	}{
		{"Authentication", wincom.Null()}, {"Encryption", wincom.UInt(99)},
		{"InterfaceType", wincom.UInt(7)}, {"InterfaceType", wincom.Null()},
		{"Direction", wincom.String("Inbound")}, {"Protocol", wincom.UInt(6)},
		{"Protocol", wincom.String("unknown")}, {"Protocol", wincom.String("256")},
		{"OverrideBlockRules", wincom.Int(0)}, {"LocalAddress", wincom.Null()},
		{"Package", wincom.Empty()}, {"Package", wincom.Bool(false)}, {"LocalPort", wincom.String("Any")}, {"Owner", wincom.String(strings.Repeat("x", 1025))},
		{"LocalPort", wincom.ArrayStrings(make([]string, 65))},
		{"LocalPort", wincom.ArrayStrings([]string{"445", "445"})},
		{"LocalPort", wincom.ArrayStrings([]string{"445\x00S:47775"})},
		{"AppPath", wincom.String("owned\x00foreign")},
	} {
		if _, err := constraintValues(tc.value, tc.field); err == nil {
			t.Fatalf("accepted unknown %s", tc.field)
		}
	}
	for _, name := range []string{"TCP", "6"} {
		parts, err := constraintValues(wincom.String(name), "Protocol")
		if err != nil || !reflect.DeepEqual(parts, []string{"N:6"}) {
			t.Fatalf("protocol representation %s: %v %v", name, parts, err)
		}
	}
	parts, err := constraintValues(wincom.ArrayStrings([]string{"20", "10"}), "LocalPort")
	if err != nil || !reflect.DeepEqual(parts, []string{"S:10", "S:20"}) {
		t.Fatalf("bounded array: %v %v", parts, err)
	}
	for _, field := range []string{"LocalPort", "RemotePort", "ServiceName", "LocalUsers", "RemoteUsers", "RemoteMachines"} {
		parts, err := constraintValues(wincom.Null(), field)
		if err != nil || !reflect.DeepEqual(parts, []string{"NULL"}) {
			t.Fatalf("explicit typed NULL %s: %v %v", field, parts, err)
		}
	}
	for _, n := range []uint32{0, 1, 2, 4} {
		parts, err := constraintValues(wincom.UInt(n), "InterfaceType")
		if err != nil || len(parts) != 1 {
			t.Fatalf("typed CIM interface type %d: %v %v", n, parts, err)
		}
	}
}

func TestNativeSessionSelectorsRemainBounded(t *testing.T) {
	for _, token := range []string{"", "bad'", strings.Repeat("a", 25)} {
		if _, err := nativeSessionSpecs(token, usbaddress.Unified, false); err == nil {
			t.Fatal("accepted invalid selector")
		}
	}
	if _, err := nativeSessionSpecs(strings.Repeat("a", 24), usbaddress.Legacy, false); err == nil {
		t.Fatal("accepted unsupported profile")
	}
	specs, err := nativeSessionSpecs(strings.Repeat("a", 24), usbaddress.Unified, false)
	if err != nil || len(specs) != 4 {
		t.Fatalf("bounded plan: %v", err)
	}
	for _, spec := range specs {
		if spec.Alias != "USB Link" || spec.Local != "10.6.9.1" || spec.Remote != "10.6.9.2" || spec.Group != serviceGroup || spec.Description != serviceMarker {
			t.Fatal("session scope changed")
		}
	}
}
