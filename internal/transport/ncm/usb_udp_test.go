package ncm

import "testing"

func usbRequest() []byte {
	mac := [6]byte{2, 3, 4, 5, 6, 7}
	f := USBUDPFrame([]byte("recovery"), mac, 47773)
	copy(f[:6], ProbeMAC[:])
	copy(f[6:12], mac[:])
	ip := f[14:]
	copy(ip[12:16], MacIP[:])
	copy(ip[16:20], WindowsIP[:])
	fixUSBChecks(f)
	return f
}
func fixUSBChecks(f []byte) {
	ip := f[14:]
	ip = ip[:int(be.Uint16(ip[2:]))]
	be.PutUint16(ip[10:], 0)
	be.PutUint16(ip[10:], Checksum(ip[:20]))
	be.PutUint16(ip[26:], 0)
	p := make([]byte, 12+len(ip)-20)
	copy(p, ip[12:20])
	p[9] = 17
	be.PutUint16(p[10:], uint16(len(ip)-20))
	copy(p[12:], ip[20:])
	sum := Checksum(p)
	if sum == 0 {
		sum = 65535
	}
	be.PutUint16(ip[26:], sum)
}
func TestUSBRecoveryDatagramBoundary(t *testing.T) {
	f := usbRequest()
	body, mac, ok := USBUDPRequest(f, 47773)
	if !ok || string(body) != "recovery" || mac != [6]byte{2, 3, 4, 5, 6, 7} {
		t.Fatal("valid packet refused")
	}
	cases := map[string]func([]byte){"other destination MAC": func(f []byte) { f[0] ^= 1 }, "multicast source": func(f []byte) { f[6] |= 1 }, "other source IP": func(f []byte) { f[29]++ }, "other destination IP": func(f []byte) { f[33]++ }, "other port": func(f []byte) { f[37]++ }, "fragment": func(f []byte) { f[20] = 0x20 }, "reserved IP flag": func(f []byte) { f[20] = 0x80 }, "UDP length mismatch": func(f []byte) { f[39]++ }, "TCP protocol": func(f []byte) { f[23] = 6 }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := usbRequest()
			mutate(f)
			fixUSBChecks(f)
			if _, _, ok := USBUDPRequest(f, 47773); ok {
				t.Fatal("accepted")
			}
		})
	}
	for _, offset := range []int{24, 40, 43} {
		f := usbRequest()
		f[offset] ^= 1
		if _, _, ok := USBUDPRequest(f, 47773); ok {
			t.Fatalf("bad checksum accepted %d", offset)
		}
	}
	if USBUDPFrame(make([]byte, 1401), mac, 47773) != nil {
		t.Fatal("oversized frame encoded")
	}
}
