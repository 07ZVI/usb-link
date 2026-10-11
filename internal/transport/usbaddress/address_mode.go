package usbaddress

// Explicit address mode is emitted only after the protected owning journal and
// fresh persistent receipt have passed. It changes no GUID/Created/origin gates.
func validHostLifetimes(mode string, valid, preferred uint32) bool {
	switch mode {
	case "":
		return valid <= 3600
	case "persistent":
		return valid == 0xffffffff && preferred == 0xffffffff
	default:
		return false
	}
}
