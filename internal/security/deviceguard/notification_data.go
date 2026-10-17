package deviceguard

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// CM_NOTIFY_EVENT_DATA: DWORD FilterType, DWORD Reserved, then the
// DeviceInstance UTF-16 union. Size and a bounded terminator are mandatory.
// https://learn.microsoft.com/windows/win32/api/cfgmgr32/ns-cfgmgr32-cm_notify_event_data
func notificationInstance(data []byte) (string, bool) {
	if len(data) < 10 || len(data) > 4096 || len(data)%2 != 0 || binary.LittleEndian.Uint32(data[:4]) != 2 || binary.LittleEndian.Uint32(data[4:8]) != 0 {
		return "", false
	}
	units := make([]uint16, 0, 200)
	for offset := 8; offset+2 <= len(data) && len(units) < 200; offset += 2 {
		v := binary.LittleEndian.Uint16(data[offset : offset+2])
		if v == 0 {
			return string(utf16.Decode(units)), len(units) > 0
		}
		units = append(units, v)
	}
	return "", false
}

// GUID_DEVINTERFACE_USB_DEVICE and its symbolic link are a wake hint only.
// Admission still reads the current native device inventory and consent.
var usbDeviceInterfaceGUID = [16]byte{0x10, 0xbf, 0xdc, 0xa5, 0x30, 0x65, 0xd2, 0x11, 0x90, 0x1f, 0, 0xc0, 0x4f, 0xb9, 0x51, 0xed}

func notificationUSBInterface(data []byte) (string, bool) {
	path, ok := notificationUSBInterfacePath(data)
	if !ok {
		return "", false
	}
	return usbInterfaceRootHint(path)
}

// A well-formed foreign USB notification is filtered, not missing evidence.
func notificationUSBInterfacePath(data []byte) (string, bool) {
	if len(data) < 26 || len(data) > 4096 || len(data)%2 != 0 || binary.LittleEndian.Uint32(data[:4]) != 0 || binary.LittleEndian.Uint32(data[4:8]) != 0 || !bytes.Equal(data[8:24], usbDeviceInterfaceGUID[:]) {
		return "", false
	}
	units := make([]uint16, 0, 256)
	for offset := 24; offset+2 <= len(data) && len(units) < 1024; offset += 2 {
		v := binary.LittleEndian.Uint16(data[offset : offset+2])
		if v == 0 {
			return string(utf16.Decode(units)), len(units) > 0
		}
		units = append(units, v)
	}
	return "", false
}

func usbInterfaceRootHint(path string) (string, bool) {
	path = strings.ToUpper(path)
	if !strings.HasPrefix(path, `\\?\USB#`) {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, `\\?\`), "#")
	if len(parts) != 4 || parts[0] != "USB" || !strings.HasPrefix(parts[1], "VID_05AC&PID_") || strings.Contains(parts[1], "&MI_") || parts[2] == "" || len(parts[2]) > 200 || strings.ContainsAny(parts[1]+parts[2], `\/`) || parts[3] != "{A5DCBF10-6530-11D2-901F-00C04FB951ED}" {
		return "", false
	}
	return strings.Join(parts[:3], `\`), true
}
