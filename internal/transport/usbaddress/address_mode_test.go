package usbaddress

import "testing"

func TestHostAddressModePreservesLegacyAndStrictInfinity(t *testing.T) {
	if !validHostLifetimes("", 3600, 3600) || validHostLifetimes("", 0xffffffff, 0xffffffff) || !validHostLifetimes("persistent", 0xffffffff, 0xffffffff) {
		t.Fatal("mode contract")
	}
	for _, x := range []struct {
		m    string
		v, p uint32
	}{{"persistent", 3600, 3600}, {"persistent", 0xffffffff, 3600}, {"unknown", 0xffffffff, 0xffffffff}} {
		if validHostLifetimes(x.m, x.v, x.p) {
			t.Fatal("invalid mode admitted", x)
		}
	}
}
