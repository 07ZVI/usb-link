package deviceguard

import (
	"encoding/binary"
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
