//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/security/deviceguard"
	"suhang/usbnet/internal/security/securitypolicy"
	"time"
)

// Local security window only. Cached hub queries neither read input events nor
// send control/descriptor requests to the attached device. Admission is unchanged.
func enrichUSBConnections(parent context.Context, nodes []securitypolicy.DeviceNode, devices []securitypolicy.DeviceRecord) {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	wanted := map[string]securitypolicy.DeviceNode{}
	for _, n := range nodes {
		id := strings.ToUpper(n.ID)
		if strings.HasPrefix(id, `USB\VID_`) && !strings.Contains(id, "&MI_") && n.DriverKey != "" {
			wanted[strings.ToUpper(n.DriverKey)] = n
		}
	}
	if len(wanted) == 0 {
		return
	}
	guid, _ := windows.GUIDFromString("{F18A0E88-C30C-11D0-8815-00A0C906BED8}")
	paths, e := windows.CM_Get_Device_Interface_List("", &guid, 0)
	if e != nil || len(paths) > 64 {
		return
	}
	values := map[string]*securitypolicy.USBConnection{}
	seen := map[string]bool{}
	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		h, e := open(path)
		if e != nil {
			continue
		}
		hub := make([]byte, 76)
		hn, he := ioctl(ctx, h, 0x220408, hub)
		if he == nil && hn >= 7 {
			ports := int(hub[6])
			if ports > 127 {
				ports = 127
			}
			for port := 1; port <= ports && ctx.Err() == nil; port++ {
				info := make([]byte, 4096)
				binary.LittleEndian.PutUint32(info, uint32(port))
				got, e := ioctl(ctx, h, 0x220448, info)
				if e != nil || got < 35 || got > uint32(len(info)) || binary.LittleEndian.Uint32(info[31:]) != 1 {
					continue
				}
				keybuf := make([]byte, 4096)
				binary.LittleEndian.PutUint32(keybuf, uint32(port))
				kn, e := ioctl(ctx, h, 0x220420, keybuf)
				if e != nil || kn < 10 {
					continue
				}
				actual := binary.LittleEndian.Uint32(keybuf[4:])
				if actual < 10 || actual > kn || actual > uint32(len(keybuf)) || actual%2 != 0 {
					continue
				}
				units := make([]uint16, (actual-8)/2)
				for i := range units {
					units[i] = binary.LittleEndian.Uint16(keybuf[8+i*2:])
				}
				if units[len(units)-1] != 0 {
					continue
				}
				key := strings.ToUpper(windows.UTF16ToString(units))
				node, ok := wanted[key]
				if !ok {
					continue
				}
				// Driver-key association also has to agree with cached descriptor identity.
				identity := strings.ToUpper(node.ID)
				vid := binary.LittleEndian.Uint16(info[12:])
				pid := binary.LittleEndian.Uint16(info[14:])
				prefix := usbDisplayID(vid, pid)
				if !strings.HasPrefix(identity, prefix) || len(identity) <= len(prefix) || (identity[len(prefix)] != '&' && identity[len(prefix)] != '\\') {
					continue
				}
				if seen[key] {
					values[key] = nil
					continue
				}
				seen[key] = true
				v2 := make([]byte, 16)
				binary.LittleEndian.PutUint32(v2, uint32(port))
				binary.LittleEndian.PutUint32(v2[4:], 16)
				binary.LittleEndian.PutUint32(v2[8:], 7)
				vn, ve := ioctl(ctx, h, 0x22045c, v2)
				if ve != nil || vn != 16 {
					v2 = nil
				}
				values[key] = deviceguard.ParseUSBConnection(info[:got], v2)
			}
		}
		windows.CloseHandle(h)
	}
	deviceguard.AssociateUSBConnections(nodes, devices, values)
}
func usbDisplayID(vid, pid uint16) string { return fmt.Sprintf(`USB\VID_%04X&PID_%04X`, vid, pid) }
