package deviceguard

import (
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
)

func hasKind(d securitypolicy.DeviceRecord, kind securitypolicy.AccessoryKind) bool {
	for _, k := range d.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Product hints affect display only. Full observed classes and admission rules
// remain intact, including auxiliary keyboard functions exposed by a mouse.
func describeDevice(d *securitypolicy.DeviceRecord, tree []securitypolicy.DeviceNode) {
	switch {
	case d.VID == "046D" && modelToken(d.Name, "G610") && hasKind(*d, securitypolicy.KindKeyboard):
		d.DisplayKind = "keyboard"
	case d.VID == "046D" && modelToken(d.Name, "G903") && hasKind(*d, securitypolicy.KindMouse):
		d.DisplayKind = "mouse"
	case d.VID == "0B05" && d.PID == "1939" && hasKind(*d, securitypolicy.KindHID) && !hasKind(*d, securitypolicy.KindKeyboard) && !hasKind(*d, securitypolicy.KindMouse):
		// OpenRGB AsusAuraUSBControllerDetect.cpp identifies this VID/PID as an
		// Aura motherboard controller. It is a product hint, not hardware proof.
		d.Name = "ASUS Aura 燈光控制器"
		d.DisplayKind = "lighting"
		d.Description = "依 VID/PID 識別為 ASUS 主板燈光控制介面（HID）；不代表鍵盤或滑鼠。"
	}
	for _, n := range tree {
		if strings.HasPrefix(strings.ToLower(n.Name), "ncm control") {
			if d.DisplayKind == "" {
				d.DisplayKind = "network"
			}
			if genericName(d.Name) || strings.HasPrefix(strings.ToLower(d.Name), "ncm control") {
				d.Name = "NCM USB 網路介面"
			}
			d.Description = "NCM Control 是 USB 網路的控制介面。"
		}
	}
}
func modelToken(name, model string) bool {
	for _, token := range strings.FieldsFunc(strings.ToUpper(name), func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') }) {
		if token == model {
			return true
		}
	}
	return false
}

// The caller supplies a fresh exact root observed by the connection manager.
// A generic NCM name or an Apple vendor ID alone never establishes ownership.
func MarkConnectionDevice(devices []securitypolicy.DeviceRecord, root, role string) {
	if root == "" || (role != "Mac" && role != "iPad") {
		return
	}
	for i := range devices {
		for _, id := range devices[i].NodeIDs {
			if strings.EqualFold(id, root) {
				devices[i].Name = role + " · USB Link 連線介面"
				devices[i].DisplayKind = "link"
				devices[i].Description = "USB Link 目前識別的 USB 網路裝置；控制與資料介面已合併顯示。"
				break
			}
		}
	}
}
