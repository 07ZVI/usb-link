package deviceguard

import (
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"testing"
)

func TestProductPresentationPreservesObservedInputClasses(t *testing.T) {
	nodes := []securitypolicy.DeviceNode{
		{ID: `USB\VID_046D&PID_C333\keyboard`, Name: "USB Composite Device", Service: "usbccgp"},
		{ID: `HID\keyboard\one`, Parent: `USB\VID_046D&PID_C333\keyboard`, Name: "G610", Service: "kbdhid"},
		{ID: `USB\VID_046D&PID_C539\mouse`, Name: "G903", Service: "usbccgp"},
		{ID: `HID\mouse\one`, Parent: `USB\VID_046D&PID_C539\mouse`, Service: "mouhid"},
		{ID: `HID\keyboard\aux`, Parent: `USB\VID_046D&PID_C539\mouse`, Service: "kbdhid"},
		{ID: `USB\VID_0B05&PID_1939\aura`, Name: "HID-compliant vendor-defined device", Service: "hidusb"},
		{ID: `USB\VID_1234&PID_1939\unknown`, Name: "HID-compliant vendor-defined device", Service: "hidusb"},
	}
	out, err := USBList(nodes, true)
	if err != nil || len(out) != 4 {
		t.Fatal(out, err)
	}
	for _, d := range out {
		switch d.VID + ":" + d.PID {
		case "046D:C333":
			if d.Name != "G610" || d.DisplayKind != "keyboard" {
				t.Fatal(d)
			}
		case "046D:C539":
			if d.DisplayKind != "mouse" || !hasKind(d, securitypolicy.KindKeyboard) {
				t.Fatal("auxiliary input class lost", d)
			}
		case "0B05:1939":
			if d.DisplayKind != "lighting" || !hasKind(d, securitypolicy.KindHID) {
				t.Fatal(d)
			}
		case "1234:1939":
			if d.DisplayKind != "" {
				t.Fatal("guessed unknown HID", d)
			}
		}
		if d.Permission != securitypolicy.PermissionPending || d.Enforcement.State != securitypolicy.Unknown {
			t.Fatal("product hint granted permission", d)
		}
	}
}
func TestConnectionAnnotationRequiresExactLocalRoot(t *testing.T) {
	root := `USB\VID_05AC&PID_1903\mac`
	nodes := []securitypolicy.DeviceNode{{ID: root, Name: "USB Composite Device", Service: "usbccgp"}, {ID: `USB\VID_05AC&PID_1903&MI_00\ncm`, Parent: root, Name: "NCM Control (Interface 0)", Service: "WinUSB"}, {ID: `USB\VID_1234&PID_5678\other`, Name: "NCM Control (Interface 0)"}}
	out, err := USBList(nodes, true)
	if err != nil {
		t.Fatal(err)
	}
	MarkConnectionDevice(out, root, "Mac")
	for _, d := range out {
		if d.VID == "05AC" {
			if d.DisplayKind != "link" {
				t.Fatal(d)
			}
		} else if d.DisplayKind == "link" {
			t.Fatal("generic NCM claimed by program", d)
		}
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "&MI_00") || strings.Contains(string(b), "node_ids") || strings.Contains(string(b), "\\\\mac") {
		t.Fatal("instance identity exported")
	}
}
func TestStorageAssociationUsesExactSubtreeNotModelOrVendor(t *testing.T) {
	root := `USB\VID_1111&PID_0001\disk`
	nodes := []securitypolicy.DeviceNode{{ID: root, Name: "USB Attached SCSI (UAS) Mass Storage Device", Service: "UASPStor"}, {ID: `SCSI\disk\usb`, Parent: root, ClassGUID: "{4d36e967-e325-11ce-bfc1-08002be10318}"}}
	out, err := USBList(nodes, true)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`[{"id":"SCSI\\disk\\internal","model":"Same SSD","bytes":2000,"volumes":[{"mount":"C:","name":"System","space_known":true,"bytes":1900,"free_bytes":100}]},{"id":"scsi\\disk\\usb","model":"Same SSD","bytes":1000,"volumes":[{"mount":"E:","name":"Data","space_known":true,"bytes":900,"free_bytes":0},{"mount":"F:","name":"Locked","space_known":false}]}]`)
	if err = applyStorage(out, raw); err != nil {
		t.Fatal(err)
	}
	if len(out[0].Storage) != 1 || out[0].Name != "Same SSD" || out[0].Storage[0].Bytes != 1000 || len(out[0].Storage[0].Volumes) != 2 || out[0].Storage[0].Volumes[0].Mount != "E:" || out[0].Storage[0].Volumes[1].SpaceKnown {
		t.Fatal("storage association or null capacity wrong", out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "SCSI") || strings.Contains(string(b), "System") {
		t.Fatal("unrelated storage leaked", string(b))
	}
	for _, bad := range []string{`[{"id":"SCSI\\disk\\usb","volumes":[{"mount":"E:","bytes":10,"free_bytes":11,"space_known":true}]}]`, `[{"id":"a"},{"id":"A"}]`, `[{"id":"a","volumes":[{"mount":"\\\\server\\share"}]}]`} {
		if applyStorage(out, []byte(bad)) == nil {
			t.Fatal("invalid storage accepted", bad)
		}
	}
}
