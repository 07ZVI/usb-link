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
