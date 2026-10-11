package ipadncm

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
	"testing"
)

func TestExactObservedSerialPaddingParsesUnchangedValueWithoutGenericException(t *testing.T) {
	for _, serial := range []string{"0123456789ABCDEF01234567", "abcdefgh-012345678._ABCD"} {
		if len(serial) != 24 {
			t.Fatal("fixture length changed")
		}
		b := identityStringFixture(serial + strings.Repeat("\x00", 16))
		original := bytes.Clone(b)
		value, status, shape, consumed := parseUSBSerialDescriptor(b, 0x12ab)
		if value != serial || status != usbSerialExactPaddingVerified || shape != nil || consumed != 16 || !bytes.Equal(b, original) {
			t.Fatal("precise padding rule did not preserve serial")
		}
		if v, s := parseUSBIdentityString(b); v != "" || s != "USB_STRING_VALUE_INVALID" {
			t.Fatal("generic/product parser unexpectedly admitted vendor padding")
		}
		if !usbDescriptorRootMatches(`USB\VID_05AC&PID_12AB\`+strings.ToUpper(serial), value) || usbDescriptorRootMatches(`USB\VID_05AC&PID_12AB\`+strings.ReplaceAll(serial, "-", ""), value) && strings.Contains(serial, "-") {
			t.Fatal("native mapping deleted characters or rejected case folding")
		}
		layout := "fixture-layout"
		grant := ipadsession.USBDescriptorGrant(value, "iPad", "12AB", layout)
		if grant != ipadsession.USBDescriptorGrant(serial, "iPad", "12AB", layout) {
			t.Fatal("padding changed grant domain/value")
		}
		preferences := ipadsession.DefaultPreferences()
		old := ipadsession.USBGrant(`USB\VID_05AC&PID_12AB\`+value, "12AB", layout)
		if !preferences.RememberUSB(old) || preferences.TrustedUSB(grant) {
			t.Fatal("padded descriptor silently promoted old instance consent")
		}
		if !preferences.RememberUSB(grant) || !preferences.TrustedUSB(grant) || len(preferences.USBDevices) != 2 {
			t.Fatal("new explicit confirmation replaced the legacy record")
		}
		// Parsing cannot supply proof of the current physical target or consent.
		unproven := usbDescriptorAttachment{root: `USB\VID_05AC&PID_12AB\` + value, hub: "fixture-hub", port: 4, serial: value, product: "iPad"}
		if unproven.same(unproven) {
			t.Fatal("parser substituted for a verified attachment")
		}
	}
}

func assertSerialFallbackUnchanged(t *testing.T, b []byte, pid uint16) {
	t.Helper()
	oldValue, oldStatus, oldShape := parseUSBIdentityStringWithFailureShape(b)
	v, s, shape, consumed := parseUSBSerialDescriptor(b, pid)
	if v != oldValue || s != oldStatus || consumed != 0 || (shape == nil) != (oldShape == nil) || shape != nil && *shape != *oldShape {
		t.Fatal("nonexact input changed baseline policy", s, oldStatus, consumed)
	}
}

func TestExactSerialPaddingRejectsEveryPrefixAndSuffixDeviation(t *testing.T) {
	base := identityStringFixture("0123456789ABCDEF01234567" + strings.Repeat("\x00", 16))
	for i := 0; i < 24; i++ {
		for _, invalid := range []uint16{0, ' ', '\t', '\n', '/', '&', ':', 0x00a0, 0x00e9, 0x0131, 0xd800, 0xfffd} {
			b := bytes.Clone(base)
			binary.LittleEndian.PutUint16(b[2+i*2:], invalid)
			assertSerialFallbackUnchanged(t, b, 0x12ab)
		}
	}
	for i := 24; i < 40; i++ {
		for _, invalid := range []uint16{'A', ' ', '\t', 0x00a0, 0x0100, 0xd800, 0xfffd} {
			b := bytes.Clone(base)
			binary.LittleEndian.PutUint16(b[2+i*2:], invalid)
			assertSerialFallbackUnchanged(t, b, 0x12ab)
		}
	}
	for _, prefix := range []int{0, 8, 23, 24, 25, 40} {
		for _, suffix := range []int{0, 1, 15, 16, 17, 32} {
			if prefix == 24 && suffix == 16 {
				continue
			}
			assertSerialFallbackUnchanged(t, identityStringFixture(strings.Repeat("A", prefix)+strings.Repeat("\x00", suffix)), 0x12ab)
		}
	}
	for _, pid := range []uint16{0, 0x12aa, 0x1903} {
		assertSerialFallbackUnchanged(t, base, pid)
	}
	for _, b := range [][]byte{base[:81], append(bytes.Clone(base), 0), append(bytes.Clone(base), 1), append(bytes.Clone(base), 0, 0)} {
		assertSerialFallbackUnchanged(t, b, 0x12ab)
	}
	for _, header := range []struct{ length, kind byte }{{80, 3}, {84, 3}, {81, 3}, {82, 2}, {0, 3}} {
		b := bytes.Clone(base)
		b[0], b[1] = header.length, header.kind
		assertSerialFallbackUnchanged(t, b, 0x12ab)
	}
}

func TestSerialParserDifferentialKeepsOriginalValidAndOtherMalformedPolicy(t *testing.T) {
	for _, serial := range []string{"0123456789ABCDEF01234567", "ABCDEF1234567890", "00008030-0012345678901234", "iPad", "iPad Pro", "e\u0301", "plain.with_-chars"} {
		assertSerialFallbackUnchanged(t, identityStringFixture(serial), 0x12ab)
	}
	rng := rand.New(rand.NewSource(879))
	for length := 0; length <= 270; length++ {
		for sample := 0; sample < 8; sample++ {
			b := make([]byte, length)
			_, _ = rng.Read(b)
			if len(b) >= 2 && sample%2 == 0 {
				b[0], b[1] = byte(length), 3
			}
			assertSerialFallbackUnchanged(t, b, 0x12ab)
		}
	}
}
