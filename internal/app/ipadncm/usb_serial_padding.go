package ipadncm

import (
	"encoding/binary"
	"suhang/usbnet/internal/transport/ipadsession"
)

const usbSerialExactPaddingVerified = "USB_SERIAL_VERIFIED_EXACT_ASCII24_NUL16_82B"

// Only the PID12AB iSerialNumber path admits the precise observed descriptor:
// 82 returned bytes, an 82/type3 header, 24 unchanged allowed ASCII units and
// exactly 16 NUL units. Product/generic decoding never uses this exception.
// This establishes a parsed serial only; fresh native binding and consent are
// still required by the existing authorization path.
func parseUSBSerialDescriptor(b []byte, pid uint16) (string, string, *USBIdentityStringFailureShape, int) {
	value, status, shape := parseUSBIdentityStringWithFailureShape(b)
	if status == "USB_STRING_VERIFIED" || pid != 0x12ab || len(b) != 82 || b[0] != 82 || b[1] != 3 {
		return value, status, shape, 0
	}
	var serial [24]byte
	for i := range serial {
		v := binary.LittleEndian.Uint16(b[2+i*2:])
		switch {
		case v >= 'A' && v <= 'Z', v >= 'a' && v <= 'z', v >= '0' && v <= '9', v == '.', v == '_', v == '-':
			serial[i] = byte(v)
		default:
			return value, status, shape, 0
		}
	}
	for i := 24; i < 40; i++ {
		if binary.LittleEndian.Uint16(b[2+i*2:]) != 0 {
			return value, status, shape, 0
		}
	}
	parsed := string(serial[:])
	if ipadsession.USBDescriptorSerialDigest(parsed) == "" {
		return value, status, shape, 0
	}
	return parsed, usbSerialExactPaddingVerified, nil, 16
}
