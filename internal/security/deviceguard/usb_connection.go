package deviceguard

import (
	"encoding/binary"
	"fmt"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
)

// ParseUSBConnection consumes packed cached hub EX/V2 structures, not active
// descriptor requests. The caller must correlate driver key and VID/PID first.
func ParseUSBConnection(info, v2 []byte) *securitypolicy.USBConnection {
	if len(info) < 35 || binary.LittleEndian.Uint32(info[31:]) != 1 || info[4] != 18 || info[5] != 1 {
		return nil
	}
	result := &securitypolicy.USBConnection{}
	bcd := binary.LittleEndian.Uint16(info[6:])
	if bcd >= 0x0100 && bcd <= 0x0999 && bcd&15 <= 9 && (bcd>>4)&15 <= 9 && (bcd>>8)&15 <= 9 {
		result.Specification = fmt.Sprintf("USB %d.%d", bcd>>8, (bcd>>4)&15)
		if bcd&15 != 0 {
			result.Specification += fmt.Sprintf("%d", bcd&15)
		}
	}
	switch info[23] {
	case 0:
		result.Speed = "1.5 Mbps"
	case 1:
		result.Speed = "12 Mbps"
	case 2:
		result.Speed = "480 Mbps"
	case 3:
		result.Speed = "5 Gbps（SuperSpeed）"
	}
	if len(v2) == 16 && binary.LittleEndian.Uint32(v2) == binary.LittleEndian.Uint32(info) && binary.LittleEndian.Uint32(v2[4:]) == 16 {
		protocols := binary.LittleEndian.Uint32(v2[8:])
		flags := binary.LittleEndian.Uint32(v2[12:])
		if protocols&^uint32(7) == 0 {
			var names []string
			if protocols&1 != 0 {
				names = append(names, "USB 1.x")
			}
			if protocols&2 != 0 {
				names = append(names, "USB 2.0")
			}
			if protocols&4 != 0 {
				names = append(names, "USB 3.x")
			}
			result.PortProtocols = strings.Join(names, " / ")
			// SuperSpeedPlus is a class (10 Gbps or higher), not proof of lane count.
			if protocols&4 != 0 && info[23] >= 2 && flags&1 != 0 {
				result.Speed = "5 Gbps（SuperSpeed）"
				if flags&4 != 0 {
					result.Speed = "10 Gbps 或以上（SuperSpeedPlus）"
				}
			}
		}
	}
	return result
}

// AssociateUSBConnections only uses a unique exact physical PnP driver key.
// Shared keys, duplicate hub observations, mismatched identity and conflicting
// merged roots leave the row unknown rather than assigning another port's data.
func AssociateUSBConnections(nodes []securitypolicy.DeviceNode, devices []securitypolicy.DeviceRecord, values map[string]*securitypolicy.USBConnection) {
	counts := map[string]int{}
	byID := map[string]securitypolicy.DeviceNode{}
	for _, n := range nodes {
		byID[strings.ToUpper(n.ID)] = n
		if physicalUSBRoot(strings.ToUpper(n.ID)) && n.DriverKey != "" {
			counts[strings.ToUpper(n.DriverKey)]++
		}
	}
	for i := range devices {
		var selected *securitypolicy.USBConnection
		conflict := false
		for _, id := range devices[i].NodeIDs {
			n := byID[strings.ToUpper(id)]
			if !physicalUSBRoot(strings.ToUpper(n.ID)) {
				continue
			}
			key := strings.ToUpper(n.DriverKey)
			if key == "" || counts[key] != 1 {
				continue
			}
			v := values[key]
			if v == nil {
				continue
			}
			if selected != nil && *selected != *v {
				conflict = true
			}
			selected = v
		}
		if !conflict {
			devices[i].USB = selected
		}
	}
}
