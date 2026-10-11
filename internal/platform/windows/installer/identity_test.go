package installer

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestExactTargets(t *testing.T) {
	for _, id := range []string{`USB\VID_05AC&PID_1903\serial`, `USB\VID_05AC&PID_19030&MI_00\serial`, `USB\VID_05AC&PID_1903&MI_00OTHER\serial`, `PCI\VID_05AC&PID_1903&MI_00\serial`} {
		if _, ok := InterfaceNumber(id); ok {
			t.Fatal("accepted non-target", id)
		}
	}
	for n := 0; n < 2; n++ {
		mi := []string{"00", "01"}[n]
		if !MatchFields("05AC", "1903", mi, "WinUSB (v6.1.7600)", "Extract Files", n) {
			t.Fatal("target rejected")
		}
	}
	if MatchFields("05AC", "1903", "02", "WinUSB", "Extract Files", 2) || MatchFields("05AC", "1903", "00", "libusbK", "Extract Files", 0) || MatchFields("05AC", "1903", "00", "WinUSB", "Install WCID Driver", 0) {
		t.Fatal("unsafe target accepted")
	}
}
func TestGeneratedINF(t *testing.T) {
	good := []byte("[Strings]\r\nDeviceID = \"VID_05AC&PID_1903&MI_00\"\r\nInclude = winusb.inf\r\nServiceBinary = %12%\\WinUSB.sys\r\n")
	if e := ValidateINF(good, 0); e != nil {
		t.Fatal(e)
	}
	if e := ValidateINF(good, 1); e == nil {
		t.Fatal("wrong interface")
	}
	for _, bad := range []string{"DeviceID = \"VID_05AC&PID_1903\"\nInclude = winusb.inf\nServiceBinary = %12%\\WinUSB.sys", "DeviceID = \"VID_05AC&PID_1903&MI_00\"\nInclude = winusb.inf\nServiceBinary = %12%\\Custom.sys"} {
		if e := ValidateINF([]byte(bad), 0); e == nil {
			t.Fatal("unsafe INF")
		}
	}
}

func encodeUTF16Fixture(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(units))
	b[0], b[1] = 0xff, 0xfe
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2+i*2:], u)
	}
	return b
}

func TestFullOfficialINFInActualOutputEncoding(t *testing.T) {
	b, err := os.ReadFile("testdata/winusb-mi00-utf16le.inf")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 3000 || b[0] != 0xff || b[1] != 0xfe {
		t.Fatal("fixture is not the complete UTF-16LE template")
	}
	if err := ValidateINF(b, 0); err != nil {
		t.Fatal(err)
	}
	if err := ValidateINF(b, 1); err == nil {
		t.Fatal("wrong interface accepted")
	}
	s, err := decodeINF(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"[libusbDevice_WinUSB.NTamd64]", "[USB_Install.Services]", "[AddDeviceInterfaceGUID]"} {
		if !strings.Contains(s, marker) {
			t.Fatal("missing complete template section", marker)
		}
	}
	for _, changed := range []string{
		strings.ReplaceAll(s, "MI_00", "MI_01"),
		strings.ReplaceAll(s, "MI_00", "MI_02"),
		strings.ReplaceAll(s, "VID_05AC", "VID_046D"),
		strings.ReplaceAll(s, `WinUSB.sys`, `Custom.sys`),
		s + "\r\nDeviceID = \"VID_05AC&PID_1903&MI_00\"\r\n",
	} {
		if err := ValidateINF(encodeUTF16Fixture(changed), 0); err == nil {
			t.Fatal("unsafe full UTF-16 INF accepted")
		}
	}
	// Non-English descriptions and surrogate pairs must round-trip exactly.
	unicode := strings.ReplaceAll(s, "NCM Control (Interface 0)", "隨航 USB 🖥")
	decoded, err := decodeINF(encodeUTF16Fixture(unicode))
	if err != nil || decoded != unicode {
		t.Fatalf("unicode roundtrip: %v", err)
	}
	if err := ValidateINF(encodeUTF16Fixture(unicode), 0); err != nil {
		t.Fatal(err)
	}
}

func TestINFRejectsMalformedEncodings(t *testing.T) {
	for _, b := range [][]byte{nil, {0xff, 0xfe, 0x41}, {0xff, 0xfe, 0, 0xd8}, {0xff, 0xfe, 0, 0xdc}, {0xff, 0xfe, 0, 0xd8, 0x41, 0}, {0xff, 0xfe, 0, 0}, {0xff}, {'D', 0, 'e', 0}} {
		if _, err := decodeINF(b); err == nil {
			t.Fatalf("accepted malformed INF %x", b)
		}
	}
	good := "DeviceID = \"VID_05AC&PID_1903&MI_00\"\nInclude = winusb.inf\nServiceBinary = %12%\\WinUSB.sys\n"
	if err := ValidateINF(append([]byte{0xef, 0xbb, 0xbf}, []byte(good)...), 0); err != nil {
		t.Fatal(err)
	}
}
