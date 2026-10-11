package ipadncm

import (
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf16"
)

func parseUSBString(b []byte) string {
	if len(b) < 2 || b[1] != 3 || int(b[0]) > len(b) || b[0] < 2 || b[0]%2 != 0 {
		return ""
	}
	u := make([]uint16, (int(b[0])-2)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2+i*2:])
	}
	s := strings.TrimSpace(string(utf16.Decode(u)))
	if len(s) > 128 || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) {
		return ""
	}
	return s
}

// Missing descriptors are presentation failures, not permission to contact
// Apple's pairing service. The qualified USB layout establishes device kind.
func usbIPadModel(product string) string {
	if strings.HasPrefix(product, "iPad") {
		return product
	}
	return "iPad"
}
