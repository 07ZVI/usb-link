package deviceguard

import (
	"suhang/usbnet/internal/security/securitypolicy"
	"testing"
)

func TestUSBListUsesEntireVerifiedSubtree(t *testing.T) {
	n := []securitypolicy.DeviceNode{{ID: `USB\VID_05AC&PID_1903\serial`, Name: "Phone", Service: "usbccgp"}, {ID: `USB\VID_05AC&PID_1903&MI_00\a`, Parent: `USB\VID_05AC&PID_1903\serial`, Service: "UsbNcm"}, {ID: `HID\keyboard\a`, Parent: `USB\VID_05AC&PID_1903&MI_00\a`, Service: "kbdhid"}, {ID: `USB\VID_1234&PID_5678\b`, Name: "Other", Service: "USBSTOR"}}
	v, err := USBList(n, true)
	if err != nil || len(v) != 2 {
		t.Fatal(v, err)
	}
	for _, r := range v {
		if r.VID != "05AC" {
			continue
		}
		if r.PID != "1903" || r.PreservedInput || r.Permission != securitypolicy.PermissionPending || r.Enforcement.State != securitypolicy.Unknown || len(r.Kinds) != 3 {
			t.Fatal("root classification wrong", r)
		}
	}
}
func TestUSBListIncompleteOrDuplicateFails(t *testing.T) {
	n := []securitypolicy.DeviceNode{{ID: `USB\VID_05AC&PID_1903\a`}}
	if _, err := USBList(n, false); err == nil {
		t.Fatal("partial inventory accepted")
	}
	n = append(n, n[0])
	if _, err := USBList(n, true); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestUSBListContainerCollapsePreservesDistinctHardware(t *testing.T) {
	nodes := []securitypolicy.DeviceNode{
		{ID: `USB\VID_0001&PID_0002\one`, Name: "Composite", ContainerID: "first", Service: "usbccgp"},
		{ID: `USB\VID_0001&PID_0003\function`, Name: "Duplicate", ContainerID: "first", Service: "USBSTOR"},
		{ID: `USB\VID_0001&PID_0002\two`, Name: "Composite", ContainerID: "second", Service: "usbccgp"},
		{ID: `HID\keyboard\one`, Parent: `USB\VID_0001&PID_0002\one`, ContainerID: "first", Service: "kbdhid"},
		{ID: `USB\VID_0010&PID_0020\hub`, Name: "Hub", ContainerID: "hub", Service: "USBHUB3"},
	}
	out, e := USBList(nodes, true)
	if e != nil || len(out) != 2 {
		t.Fatal(out, e)
	}
	for _, r := range out {
		if r.Name == "Duplicate" {
			t.Fatal("duplicate physical row")
		}
		if r.Name == "Composite" && len(r.Kinds) == 3 {
			return
		}
	}
	t.Fatal("collapsed functions lost", out)
}
func TestUSBListIdenticalNamesWithoutContainersRemainSeparate(t *testing.T) {
	out, e := USBList([]securitypolicy.DeviceNode{{ID: `USB\VID_0001&PID_0002\one`, Name: "Same"}, {ID: `USB\VID_0001&PID_0002\two`, Name: "Same"}}, true)
	if e != nil || len(out) != 2 || out[0].Handle == out[1].Handle {
		t.Fatal(out, e)
	}
}

func TestUSBListTopologyGroupingAndEmptyPorts(t *testing.T) {
	root := `USB\VID_046D&PID_C333\G610`
	nodes := []securitypolicy.DeviceNode{
		{ID: root, Name: "G610", Service: "usbccgp", LocationPaths: []string{"PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(3)"}},
		{ID: `USB\VID_046D&PID_C334\function`, Name: "G610", Parent: root, Service: "kbdhid"},
		{ID: `USB\VID_046D&PID_C333\second`, Name: "G610", Service: "kbdhid", LocationPaths: []string{"PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(4)"}},
		{ID: `USB\VID_1111&PID_0001\storage`, Name: "Disk", Service: "USBSTOR"},
		{ID: `USB\VID_1111&PID_0002\unknown`, Name: "Unknown"},
		{ID: `USB\ROOT_HUB30\empty`, Name: "Root hub", Service: "USBHUB3"},
		{ID: `USB\VID_2222&PID_0001\empty`, Name: "Empty hub", Service: "USBHUB3"},
	}
	out, err := USBList(nodes, true)
	if err != nil || len(out) != 4 {
		t.Fatal(out, err)
	}
	if out[0].Name != "G610" || out[1].Name != "G610" || out[2].Name != "Disk" || out[3].Name != "Unknown" {
		t.Fatal("input-first and unknown-last ordering", out)
	}
	merged := 0
	for _, d := range out {
		if d.MergedRoots == 2 {
			merged++
			if d.NodeCount != 2 || len(d.Kinds) != 2 {
				t.Fatal("lost composite functions", d)
			}
		}
	}
	if merged != 1 {
		t.Fatal("same physical parent not collapsed", out)
	}
}
func TestUSBListPortFallbackDoesNotMergeOtherHubPorts(t *testing.T) {
	base := "PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(3)"
	nodes := []securitypolicy.DeviceNode{
		{ID: `USB\VID_046D&PID_C333\one`, Name: "G610", LocationPaths: []string{base}},
		{ID: `USB\VID_046D&PID_C334\function`, Name: "G610", Service: "kbdhid", LocationPaths: []string{base + "#USBMI(1)"}},
		{ID: `USB\VID_046D&PID_C333\two`, Name: "G610", LocationPaths: []string{base + "#USB(1)"}},
	}
	out, err := USBList(nodes, true)
	if err != nil || len(out) != 2 {
		t.Fatal(out, err)
	}
	for _, d := range out {
		if d.MergedRoots == 2 && d.NodeCount != 2 {
			t.Fatal("wrong physical port merged", d)
		}
	}
}
func TestUSBListContainerConflictCannotBridgeDistinctPorts(t *testing.T) {
	nodes := []securitypolicy.DeviceNode{
		{ID: `USB\VID_0001&PID_0001\one`, Name: "Keyboard", ContainerID: "faulty", LocationPaths: []string{"USBROOT(0)#USB(1)"}},
		{ID: `USB\VID_0001&PID_0001\unknown`, Name: "Keyboard", ContainerID: "faulty"},
		{ID: `USB\VID_0001&PID_0001\two`, Name: "Keyboard", ContainerID: "faulty", LocationPaths: []string{"USBROOT(0)#USB(2)"}},
	}
	out, err := USBList(nodes, true)
	if err != nil || len(out) != 3 {
		t.Fatal("conflicting container merged distinct physical ports", out, err)
	}
}
func TestUSBListOccupiedHubKeepsChildrenIndependent(t *testing.T) {
	hub := `USB\VID_2222&PID_0001\hub`
	out, err := USBList([]securitypolicy.DeviceNode{{ID: hub, Name: "Hub", Service: "USBHUB3"}, {ID: `USB\VID_3333&PID_0001\child`, Parent: hub, Name: "Keyboard", Service: "kbdhid"}}, true)
	if err != nil || len(out) != 2 || out[0].Name != "Keyboard" || out[1].Name != "Hub" || len(out[1].Kinds) != 1 {
		t.Fatal("hub swallowed its downstream input", out, err)
	}
}
