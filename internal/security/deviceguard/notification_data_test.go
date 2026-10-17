package deviceguard

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestNotificationMetadataRejectsTruncatedForeignAndUnterminatedData(t *testing.T) {
	name := `USB\VID_05AC&PID_1903\example`
	units := append(utf16.Encode([]rune(name)), 0)
	data := make([]byte, 8+2*len(units))
	binary.LittleEndian.PutUint32(data, 2)
	for i, v := range units {
		binary.LittleEndian.PutUint16(data[8+i*2:], v)
	}
	if got, ok := notificationInstance(data); !ok || got != name {
		t.Fatal(got, ok)
	}
	for _, malformed := range [][]byte{nil, data[:7], data[:len(data)-1], data[:len(data)-2], make([]byte, 4098)} {
		if _, ok := notificationInstance(malformed); ok {
			t.Fatal("accepted malformed event")
		}
	}
	data[0] = 1
	if _, ok := notificationInstance(data); ok {
		t.Fatal("accepted interface event as instance")
	}
	data[0], data[4] = 2, 1
	if _, ok := notificationInstance(data); ok {
		t.Fatal("accepted reserved field")
	}
}

func TestUSBInterfaceNotificationIsOnlyAnExactAppleRootWakeHint(t *testing.T) {
	path := `\\?\usb#vid_05ac&pid_12ab#example#{a5dcbf10-6530-11d2-901f-00c04fb951ed}`
	units := append(utf16.Encode([]rune(path)), 0)
	data := make([]byte, 24+2*len(units))
	copy(data[8:24], usbDeviceInterfaceGUID[:])
	for i, v := range units {
		binary.LittleEndian.PutUint16(data[24+i*2:], v)
	}
	if got, ok := notificationUSBInterface(data); !ok || got != `USB\VID_05AC&PID_12AB\EXAMPLE` {
		t.Fatal(got, ok)
	}
	for _, malformed := range [][]byte{nil, data[:24], data[:len(data)-1], data[:len(data)-2], make([]byte, 4098)} {
		if _, ok := notificationUSBInterface(malformed); ok {
			t.Fatal("accepted malformed USB notification")
		}
	}
	for _, offset := range []int{0, 4, 8} {
		bad := append([]byte(nil), data...)
		bad[offset] ^= 1
		if _, ok := notificationUSBInterface(bad); ok {
			t.Fatal("accepted wrong union/reserved/class", offset)
		}
	}
	for _, other := range []string{
		`\\?\USB#VID_05AC&PID_12AB&MI_00#example#{A5DCBF10-6530-11D2-901F-00C04FB951ED}`,
		`\\?\USB#VID_0000&PID_12AB#example#{A5DCBF10-6530-11D2-901F-00C04FB951ED}`,
		`\\?\USB#VID_05AC&PID_12AB##{A5DCBF10-6530-11D2-901F-00C04FB951ED}`,
		`\\?\USB#VID_05AC&PID_12AB#other\child#{A5DCBF10-6530-11D2-901F-00C04FB951ED}`,
	} {
		if _, ok := usbInterfaceRootHint(other); ok {
			t.Fatal("accepted child/foreign/invalid path")
		}
	}
}

func TestForeignUSBNotificationIsParsedBeforeCandidateFiltering(t *testing.T) {
	path := `\\?\USB#VID_1234&PID_5678#foreign#{A5DCBF10-6530-11D2-901F-00C04FB951ED}`
	units := append(utf16.Encode([]rune(path)), 0)
	data := make([]byte, 24+2*len(units))
	copy(data[8:24], usbDeviceInterfaceGUID[:])
	for i, v := range units {
		binary.LittleEndian.PutUint16(data[24+i*2:], v)
	}
	if got, ok := notificationUSBInterfacePath(data); !ok || got != path {
		t.Fatal("well-formed foreign callback mistaken for parse loss", got, ok)
	}
	if _, ok := notificationUSBInterface(data); ok {
		t.Fatal("foreign callback accepted as Apple root")
	}
	if _, ok := notificationUSBInterfacePath(data[:len(data)-2]); ok {
		t.Fatal("unterminated native data accepted")
	}
}
