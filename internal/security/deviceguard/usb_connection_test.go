package deviceguard

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"testing"
)

func TestCachedUSBConnection(t *testing.T) {
	info := make([]byte, 35)
	binary.LittleEndian.PutUint32(info, 3)
	info[4] = 18
	info[5] = 1
	binary.LittleEndian.PutUint16(info[6:], 0x0320)
	info[23] = 2
	binary.LittleEndian.PutUint32(info[31:], 1)
	v2 := make([]byte, 16)
	binary.LittleEndian.PutUint32(v2, 3)
	binary.LittleEndian.PutUint32(v2[4:], 16)
	binary.LittleEndian.PutUint32(v2[8:], 7)
	binary.LittleEndian.PutUint32(v2[12:], 15)
	v := ParseUSBConnection(info, v2)
	if v.Specification != "USB 3.2" || !strings.Contains(v.Speed, "10 Gbps 或以上") || v.PortProtocols != "USB 1.x / USB 2.0 / USB 3.x" {
		t.Fatalf("unexpected cached revision/link: %+v", v)
	}
	binary.LittleEndian.PutUint32(v2[12:], 2|8)
	v = ParseUSBConnection(info, v2)
	if v.Speed != "480 Mbps" {
		t.Fatal("capability must not imply negotiated speed")
	}
	binary.LittleEndian.PutUint32(v2[12:], 1)
	v = ParseUSBConnection(info, v2)
	if v.Speed != "5 Gbps（SuperSpeed）" || v.Specification != "USB 3.2" {
		t.Fatal("device revision and current link must be independent")
	}
	binary.LittleEndian.PutUint32(v2, 4)
	v = ParseUSBConnection(info, v2)
	if v.PortProtocols != "" || v.Speed != "480 Mbps" {
		t.Fatal("different port must not supply link flags")
	}
	binary.LittleEndian.PutUint16(info[6:], 0x03a0)
	if ParseUSBConnection(info, nil).Specification != "" {
		t.Fatal("invalid BCD revision")
	}
	binary.LittleEndian.PutUint32(info[31:], 0)
	if ParseUSBConnection(info, nil) != nil || ParseUSBConnection(info[:20], nil) != nil {
		t.Fatal("disconnected/short metadata accepted")
	}
}

func TestUSBDriverKeyAssociation(t *testing.T) {
	nodes := []securitypolicy.DeviceNode{{ID: `USB\VID_1234&PID_5678\A`, DriverKey: "KEY"}, {ID: `HID\VID_1234&PID_5678\A`, DriverKey: "KEY"}}
	records := []securitypolicy.DeviceRecord{{NodeIDs: []string{nodes[0].ID, nodes[1].ID}}}
	v := &securitypolicy.USBConnection{Specification: "USB 3.1"}
	AssociateUSBConnections(nodes, records, map[string]*securitypolicy.USBConnection{"KEY": v})
	if records[0].USB != v {
		t.Fatal("exact physical driver key not matched")
	}
	records[0].USB = nil
	nodes = append(nodes, securitypolicy.DeviceNode{ID: `USB\VID_1234&PID_5678\B`, DriverKey: "KEY"})
	AssociateUSBConnections(nodes, records, map[string]*securitypolicy.USBConnection{"KEY": v})
	if records[0].USB != nil {
		t.Fatal("duplicate physical driver key accepted")
	}
	encoded, _ := json.Marshal(nodes[0])
	if strings.Contains(string(encoded), "KEY") || strings.Contains(string(encoded), "VID_") {
		t.Fatal("local USB identity exported")
	}
	records[0].USB = nil
	nodes[2].DriverKey = "OTHER"
	records[0].NodeIDs = append(records[0].NodeIDs, nodes[2].ID)
	AssociateUSBConnections(nodes, records, map[string]*securitypolicy.USBConnection{"KEY": v, "OTHER": {Specification: "USB 2.0"}})
	if records[0].USB != nil {
		t.Fatal("conflicting grouped revisions must remain unknown")
	}
}
