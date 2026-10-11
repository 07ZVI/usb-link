package ipadncm

import (
	"encoding/binary"
	"unicode"
	"unicode/utf16"
)

// USBIdentityStringFailureShape exposes aggregates only. No characters, raw
// bytes, exact positions, value digest or reversible encoding leave this type.
// Payload inspection is capped at the USB string descriptor's 255-byte limit.
type USBIdentityStringFailureShape struct {
	ReceivedBytes                int  `json:"received_bytes_capped_at_255"`
	InputExceedsLimit            bool `json:"input_exceeds_255_bytes"`
	HeaderPresent                bool `json:"header_present"`
	DeclaredBytes                int  `json:"declared_blength"`
	StringDescriptorType         bool `json:"string_descriptor_type"`
	LengthConsistent             bool `json:"length_consistent"`
	PayloadUTF16Units            int  `json:"payload_utf16_units"`
	PayloadOddBytes              int  `json:"payload_odd_bytes"`
	DecodedUTF8Bytes             int  `json:"decoded_utf8_bytes"`
	TerminalNULUnits             int  `json:"terminal_nul_units"`
	OtherNULUnits                int  `json:"other_nul_units"`
	ControlRunes                 int  `json:"control_runes"`
	LeadingControlRunes          int  `json:"leading_control_runes"`
	EmbeddedControlRunes         int  `json:"embedded_control_runes"`
	TrailingControlRunes         int  `json:"trailing_control_runes"`
	SpaceRunes                   int  `json:"unicode_space_runes"`
	LeadingSpaceRunes            int  `json:"leading_space_runes"`
	EmbeddedSpaceRunes           int  `json:"embedded_space_runes"`
	TrailingSpaceRunes           int  `json:"trailing_space_runes"`
	ASCIIAllowedSerialUnits      int  `json:"ascii_serial_allowed_units"`
	ASCIIOtherUnits              int  `json:"ascii_other_units"`
	NonASCIIUnits                int  `json:"non_ascii_units"`
	SurrogatePairs               int  `json:"surrogate_pairs"`
	UnpairedSurrogateUnits       int  `json:"unpaired_surrogate_units"`
	LiteralReplacementUnits      int  `json:"literal_replacement_units"`
	TrailingDescriptorZeroBytes  int  `json:"outside_blength_zero_bytes"`
	TrailingDescriptorOtherBytes int  `json:"outside_blength_nonzero_bytes"`
}

func parseUSBIdentityStringWithFailureShape(b []byte) (string, string, *USBIdentityStringFailureShape) {
	value, status := parseUSBIdentityString(b)
	if status == "USB_STRING_VERIFIED" {
		return value, status, nil
	}
	shape := usbIdentityStringFailureShape(b)
	return value, status, &shape
}

func usbIdentityStringFailureShape(b []byte) USBIdentityStringFailureShape {
	s := USBIdentityStringFailureShape{ReceivedBytes: len(b)}
	if len(b) > 255 {
		b = b[:255]
		s.ReceivedBytes, s.InputExceedsLimit = len(b), true
	}
	if len(b) < 2 {
		return s
	}
	s.HeaderPresent, s.DeclaredBytes, s.StringDescriptorType = true, int(b[0]), b[1] == 3
	s.LengthConsistent = s.DeclaredBytes >= 4 && s.DeclaredBytes%2 == 0 && s.DeclaredBytes <= len(b)
	end := min(s.DeclaredBytes, len(b))
	if end < 2 {
		return s
	}
	for _, v := range b[end:] {
		if v == 0 {
			s.TrailingDescriptorZeroBytes++
		} else {
			s.TrailingDescriptorOtherBytes++
		}
	}
	s.PayloadUTF16Units, s.PayloadOddBytes = (end-2)/2, (end-2)%2
	u := make([]uint16, s.PayloadUTF16Units)
	for i := range u {
		v := binary.LittleEndian.Uint16(b[2+i*2:])
		u[i] = v
		if v == 0 {
			s.OtherNULUnits++
		}
		if v == 0xfffd {
			s.LiteralReplacementUnits++
		}
		switch {
		case v >= 'A' && v <= 'Z', v >= 'a' && v <= 'z', v >= '0' && v <= '9', v == '.', v == '_', v == '-':
			s.ASCIIAllowedSerialUnits++
		case v < 128:
			s.ASCIIOtherUnits++
		default:
			s.NonASCIIUnits++
		}
	}
	for i := len(u) - 1; i >= 0 && u[i] == 0; i-- {
		s.TerminalNULUnits++
		s.OtherNULUnits--
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 < len(u) && u[i+1] >= 0xdc00 && u[i+1] <= 0xdfff {
				s.SurrogatePairs++
				i++
			} else {
				s.UnpairedSurrogateUnits++
			}
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			s.UnpairedSurrogateUnits++
		}
	}
	r := utf16.Decode(u)
	s.DecodedUTF8Bytes = len(string(r))
	s.ControlRunes, s.LeadingControlRunes, s.EmbeddedControlRunes, s.TrailingControlRunes = usbIdentityCategoryCounts(r, unicode.IsControl)
	s.SpaceRunes, s.LeadingSpaceRunes, s.EmbeddedSpaceRunes, s.TrailingSpaceRunes = usbIdentityCategoryCounts(r, unicode.IsSpace)
	return s
}

// For an all-category string, leading owns the entire run and trailing is zero;
// the three position classes partition the total without reporting any index.
func usbIdentityCategoryCounts(r []rune, isCategory func(rune) bool) (total, leading, embedded, trailing int) {
	for _, v := range r {
		if isCategory(v) {
			total++
		}
	}
	for leading < len(r) && isCategory(r[leading]) {
		leading++
	}
	for i := len(r) - 1; i >= leading && isCategory(r[i]); i-- {
		trailing++
	}
	return total, leading, total - leading - trailing, trailing
}
