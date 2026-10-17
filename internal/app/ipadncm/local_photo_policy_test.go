package ipadncm

import "testing"

func TestPhotoPolicyWindowsSupportIsExplicit(t *testing.T) {
	for _, sku := range []uint32{0x30, 0x31, 0x04, 0x79, 0x7d, 0xbc, 0xbf} {
		if !photoPolicySupported(10, 19041, sku, true) {
			t.Fatal(sku)
		}
	}
	for _, v := range []struct {
		major, build, sku uint32
		client            bool
	}{{10, 19040, 0x30, true}, {10, 26100, 0x65, true}, {10, 26100, 0x30, false}, {6, 19041, 0x30, true}, {10, 26100, 0xffff, true}} {
		if photoPolicySupported(v.major, v.build, v.sku, v.client) {
			t.Fatal(v)
		}
	}
}
