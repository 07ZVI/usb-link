package ipadncm

import (
	"context"
	"encoding/binary"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
	"unicode"
	"unicode/utf16"
)

// Identity decoding does not trim, repair invalid surrogate pairs, or invent a
// model when the descriptor is missing. Presentation fallback remains separate.
func parseUSBIdentityString(b []byte) (string, string) {
	if len(b) < 2 || len(b) > 255 || b[1] != 3 || b[0] < 4 || b[0]%2 != 0 || int(b[0]) > len(b) {
		return "", "USB_STRING_LENGTH_OR_TYPE_INVALID"
	}
	for _, padding := range b[int(b[0]):] {
		if padding != 0 {
			return "", "USB_STRING_TRAILING_DATA"
		}
	}
	u := make([]uint16, (int(b[0])-2)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2+i*2:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", "USB_STRING_UTF16_INVALID"
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return "", "USB_STRING_UTF16_INVALID"
		}
	}
	s := string(utf16.Decode(u))
	if s == "" || len(s) > 128 || strings.TrimSpace(s) != s || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) {
		return "", "USB_STRING_VALUE_INVALID"
	}
	return s, "USB_STRING_VERIFIED"
}

func usbIdentityLanguage(b []byte) (uint16, string) {
	if len(b) < 4 || len(b) > 255 || b[1] != 3 || b[0] < 4 || b[0]%2 != 0 || int(b[0]) > len(b) {
		return 0, "USB_LANGID_DESCRIPTOR_INVALID"
	}
	for _, padding := range b[int(b[0]):] {
		if padding != 0 {
			return 0, "USB_LANGID_TRAILING_DATA"
		}
	}
	seen := map[uint16]bool{}
	for i := 2; i < int(b[0]); i += 2 {
		lang := binary.LittleEndian.Uint16(b[i:])
		if lang == 0 || seen[lang] {
			return 0, "USB_LANGID_ZERO_OR_DUPLICATE"
		}
		seen[lang] = true
	}
	return binary.LittleEndian.Uint16(b[2:]), "USB_LANGID_VERIFIED"
}

type usbDescriptorAttachment struct {
	root, hub, serial, product string // Private: never exported or logged.
	port                       uint32
	verified                   bool
}

func (a usbDescriptorAttachment) same(b usbDescriptorAttachment) bool {
	return a.verified && b.verified && a.root != "" && a.hub != "" && a.port != 0 && strings.EqualFold(a.root, b.root) && strings.EqualFold(a.hub, b.hub) && a.port == b.port && a.serial == b.serial && a.product == b.product && ipadsession.ValidUSBDescriptorIdentity(a.serial, a.product) && ipadsession.ValidUSBDescriptorIdentity(b.serial, b.product)
}

func currentUSBDescriptorPermission(ctx context.Context, granted, current usbDescriptorAttachment) bool {
	return ctx != nil && ctx.Err() == nil && granted.same(current)
}

// This strict native-to-descriptor match deliberately does not guess aliasing,
// delete hyphens, or turn a location-generated instance into a serial number.
func usbDescriptorRootMatches(root, serial string) bool {
	parts := strings.Split(root, `\`)
	return len(parts) == 3 && strings.EqualFold(parts[0]+`\`+parts[1], `USB\VID_05AC&PID_12AB`) && ipadsession.USBDescriptorSerialDigest(serial) != "" && strings.EqualFold(parts[2], serial)
}
