package netconfig

import (
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func validNativeHostNode() nativeHostNode {
	key := hostNetClass + `\0004`
	return nativeHostNode{Instance: `SWD\WINTUN\owned`, CMInstance: `SWD\WINTUN\owned`, SetupClass: hostNetClass, CMClass: hostNetClass, Service: "Wintun", SetupDriver: key, CMDriver: key, SetupNetGUID: usbaddress.HostGUID, CMNetGUID: usbaddress.HostGUID, DevInst: 45, ServiceType: 18, ServiceSize: 14, ClassType: 13, ClassSize: 16, DriverType: 18, DriverSize: uint32((len(key) + 1) * 2), StateReadable: true}
}

func TestNativeHostRejectsMixedDeviceOwnership(t *testing.T) {
	if e := validateNativeHostNode(validNativeHostNode()); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*nativeHostNode){
		"other-instance":    func(n *nativeHostNode) { n.CMInstance = `SWD\WINTUN\foreign` },
		"wildcard-instance": func(n *nativeHostNode) { n.Instance = "*"; n.CMInstance = "*" },
		"missing-instance":  func(n *nativeHostNode) { n.Instance = "" },
		"other-service":     func(n *nativeHostNode) { n.Service = "UsbNcm" },
		"untyped-service":   func(n *nativeHostNode) { n.ServiceType = 0 },
		"truncated-service": func(n *nativeHostNode) { n.ServiceSize = 12 },
		"other-class":       func(n *nativeHostNode) { n.CMClass = "{88bae032-5a81-49f0-bc3d-a4ff138216d6}" },
		"setup-class":       func(n *nativeHostNode) { n.SetupClass = "other" },
		"class-size":        func(n *nativeHostNode) { n.ClassSize = 32 },
		"class-type":        func(n *nativeHostNode) { n.ClassType = 18 },
		"other-driver-key":  func(n *nativeHostNode) { n.CMDriver = hostNetClass + `\0005` },
		"path-driver-key":   func(n *nativeHostNode) { n.SetupDriver = `..\0004` },
		"driver-type":       func(n *nativeHostNode) { n.DriverType = 0 },
		"driver-size":       func(n *nativeHostNode) { n.DriverSize++ },
		"other-native-guid": func(n *nativeHostNode) { n.CMNetGUID = "{00000000-0000-0000-0000-000000000001}" },
		"other-setup-guid": func(n *nativeHostNode) {
			n.SetupNetGUID = "{00000000-0000-0000-0000-000000000001}"
			n.CMNetGUID = n.SetupNetGUID
		},
		"missing-cm-node":  func(n *nativeHostNode) { n.DevInst = 0 },
		"state-unreadable": func(n *nativeHostNode) { n.StateReadable = false },
		"state-problem":    func(n *nativeHostNode) { n.Problem = 22 },
	} {
		t.Run(name, func(t *testing.T) {
			n := validNativeHostNode()
			change(&n)
			if validateNativeHostNode(n) == nil {
				t.Fatal("mixed or unreadable ownership accepted")
			}
		})
	}
}

func TestNativeHostMappingRejectsAliasOnlyAndRemappedScope(t *testing.T) {
	f := nativeHostInterface{GUID: usbaddress.HostGUID, Alias: usbaddress.HostName, Type: 53, Index: 28, LUID: 280}
	if _, e := validateNativeHostInterface([]nativeHostInterface{f}, 28); e != nil {
		t.Fatal(e)
	}
	for _, v := range [][]nativeHostInterface{nil, {f, f}, {{GUID: "other", Alias: f.Alias, Type: 53, Index: 28, LUID: 280}}, {{GUID: f.GUID, Alias: "other", Type: 53, Index: 28, LUID: 280}}, {{GUID: f.GUID, Alias: f.Alias, Type: 6, Index: 28, LUID: 280}}, {{GUID: f.GUID, Alias: f.Alias, Type: 53, Index: 29, LUID: 280}}, {{GUID: f.GUID, Alias: f.Alias, Type: 53, Index: 28, LUID: 0}}} {
		if _, e := validateNativeHostInterface(v, 28); e == nil {
			t.Fatal("unknown/mixed/multiple mapping accepted")
		}
	}
}

func TestNativeHostStringRejectsPropertyShapeChanges(t *testing.T) {
	if s, ok := decodeNativeHostString([]uint16{'W', 'i', 'n', 't', 'u', 'n', 0}, 14); !ok || s != "Wintun" {
		t.Fatal(s, ok)
	}
	for _, v := range []struct {
		b    []uint16
		size uint32
	}{{[]uint16{'W', 0}, 3}, {[]uint16{'W', 0}, 6}, {[]uint16{'W', 'x'}, 4}, {[]uint16{0, 'x', 0}, 6}, {[]uint16{0xd800, 0}, 4}, {[]uint16{0xdc00, 0}, 4}} {
		if _, ok := decodeNativeHostString(v.b, v.size); ok {
			t.Fatal("invalid native property accepted")
		}
	}
}

func TestNativeHostFreshRecheckRejectsReplacement(t *testing.T) {
	f := nativeHostInterface{GUID: usbaddress.HostGUID, Alias: usbaddress.HostName, Type: 53, Index: 28, LUID: 280}
	n := validNativeHostNode()
	if e := validateNativeHostTransition(f, f, n, n); e != nil {
		t.Fatal(e)
	}
	other := f
	other.LUID++
	if validateNativeHostTransition(f, other, n, n) == nil {
		t.Fatal("fresh remapping admitted")
	}
	otherNode := n
	otherNode.DevInst++
	if validateNativeHostTransition(f, f, n, otherNode) == nil {
		t.Fatal("replacement native devnode admitted")
	}
	otherNode = n
	otherNode.Instance = `SWD\WINTUN\replacement`
	otherNode.CMInstance = otherNode.Instance
	if validateNativeHostTransition(f, f, n, otherNode) == nil {
		t.Fatal("another healthy Wintun node admitted")
	}
}
