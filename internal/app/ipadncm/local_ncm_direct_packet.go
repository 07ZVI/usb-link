//go:build usblink_local_remote

package ipadncm

// Keep the experimental write separate from the ordinary mode-3 allowlist.
func localDirectMode5Packet() []byte {
	return []byte{0xc0, 0x52, 0, 0, 5, 0, 1, 0, 0}
}

// This is descriptor evidence only. It does not prove DHCP/IPv4 capability.
func directOnlyNCMLayout(configs []Configuration, current byte) bool {
	if len(configs) != 1 || current != 1 || configs[0].Value != 1 || configs[0].NCMControls != 1 {
		return false
	}
	control, data := 0, 0
	for _, i := range configs[0].Interfaces {
		switch {
		case i.Class == 2 && i.Subclass == 13:
			control++
		case i.Class == 10:
			data++
		default:
			return false
		}
	}
	return control == 1 && data > 0 && data <= 2
}
