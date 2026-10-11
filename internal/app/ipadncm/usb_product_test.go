package ipadncm

import "testing"

func TestUSBProductDescriptorFallbackAndBounds(t *testing.T) {
	valid := []byte{10, 3, 'i', 0, 'P', 0, 'a', 0, 'd', 0}
	if parseUSBString(valid) != "iPad" || usbIPadModel("") != "iPad" || usbIPadModel("iPad Pro") != "iPad Pro" {
		t.Fatal("descriptor model")
	}
	for _, b := range [][]byte{nil, {4, 3, 'i'}, {3, 3, 0}, {4, 2, 'i', 0}, {4, 3, 0, 0}, {4, 3, 0, 0xd8}} {
		if parseUSBString(b) != "" {
			t.Fatal("invalid descriptor accepted", b)
		}
	}
}
