package ipadncm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestUSBDescriptorFailureShapeSeparatesTerminatorFromPayloadAndPadding(t *testing.T) {
	b := append(identityStringFixture("1234\x005678\x00\x00"), 0, 0, 0)
	v, status, shape := parseUSBIdentityStringWithFailureShape(b)
	if v != "" || status != "USB_STRING_VALUE_INVALID" || shape == nil {
		t.Fatal("diagnostics changed rejection")
	}
	if shape.ReceivedBytes != 27 || shape.DeclaredBytes != 24 || shape.PayloadUTF16Units != 11 || shape.DecodedUTF8Bytes != 11 || shape.TerminalNULUnits != 2 || shape.OtherNULUnits != 1 || shape.ControlRunes != 3 || shape.EmbeddedControlRunes != 1 || shape.TrailingControlRunes != 2 || shape.ASCIIAllowedSerialUnits != 8 || shape.TrailingDescriptorZeroBytes != 3 || !shape.LengthConsistent {
		t.Fatal("payload termination and outer zero padding conflated", shape)
	}
}

func TestUSBDescriptorFailureShapeGroupsWhitespaceWithoutLeakingPosition(t *testing.T) {
	shape := usbIdentityStringFailureShape(identityStringFixture("\t A B\u00a0\n"))
	if shape.SpaceRunes != 5 || shape.LeadingSpaceRunes != 2 || shape.EmbeddedSpaceRunes != 1 || shape.TrailingSpaceRunes != 2 || shape.ControlRunes != 2 || shape.LeadingControlRunes != 1 || shape.TrailingControlRunes != 1 || shape.ASCIIAllowedSerialUnits != 2 || shape.NonASCIIUnits != 1 || shape.DecodedUTF8Bytes != 8 {
		t.Fatal("whitespace/control categories incorrect", shape)
	}
	shape = usbIdentityStringFailureShape(identityStringFixture("\t\n"))
	if shape.LeadingSpaceRunes != 2 || shape.TrailingSpaceRunes != 0 || shape.EmbeddedSpaceRunes != 0 {
		t.Fatal("all-category observation double counted", shape)
	}
}

func TestUSBDescriptorFailureShapePreservesNegativeDecoderOutcomes(t *testing.T) {
	cases := []struct {
		input  []byte
		status string
	}{
		{nil, "USB_STRING_LENGTH_OR_TYPE_INVALID"},
		{[]byte{4, 3, 'x'}, "USB_STRING_LENGTH_OR_TYPE_INVALID"},
		{[]byte{5, 3, 'x', 0, 0}, "USB_STRING_LENGTH_OR_TYPE_INVALID"},
		{[]byte{4, 2, 'x', 0}, "USB_STRING_LENGTH_OR_TYPE_INVALID"},
		{[]byte{4, 3, 0, 0xd8}, "USB_STRING_UTF16_INVALID"},
		{[]byte{4, 3, 0, 0xdc}, "USB_STRING_UTF16_INVALID"},
		{identityStringFixture("ABCDEF123456\x00"), "USB_STRING_VALUE_INVALID"},
		{identityStringFixture(" ABCDEF123456"), "USB_STRING_VALUE_INVALID"},
		{identityStringFixture("ABCDEF123456\ufffd"), "USB_STRING_VALUE_INVALID"},
		{identityStringFixture(strings.Repeat("\u00e9", 65)), "USB_STRING_VALUE_INVALID"},
		{append(identityStringFixture("ABCDEF123456"), 7), "USB_STRING_TRAILING_DATA"},
	}
	for _, c := range cases {
		value, status, shape := parseUSBIdentityStringWithFailureShape(c.input)
		if value != "" || status != c.status || shape == nil {
			t.Fatal("rejected value repaired or status changed", status, c.status)
		}
	}
	paired := usbIdentityStringFailureShape(identityStringFixture("\U0001f600\ufffd"))
	if paired.SurrogatePairs != 1 || paired.UnpairedSurrogateUnits != 0 || paired.LiteralReplacementUnits != 1 || paired.PayloadUTF16Units != 3 || paired.DecodedUTF8Bytes != 7 {
		t.Fatal("surrogates and literal replacement conflated", paired)
	}
	broken := usbIdentityStringFailureShape([]byte{6, 3, 0, 0xd8, 'x', 0})
	if broken.UnpairedSurrogateUnits != 1 || broken.LiteralReplacementUnits != 0 {
		t.Fatal("decoder replacement invented a literal input", broken)
	}
}

func TestUSBDescriptorShapeWrapperIsDifferentiallyEquivalentToUnchangedParser(t *testing.T) {
	rng := rand.New(rand.NewSource(733))
	inputs := [][]byte{identityStringFixture("iPad"), identityStringFixture("00008030-0012345678901234"), identityStringFixture("iPad Pro"), identityStringFixture("1234567890\x00")}
	for length := 0; length <= 270; length++ {
		for sample := 0; sample < 8; sample++ {
			b := make([]byte, length)
			_, _ = rng.Read(b)
			if len(b) >= 2 && sample%2 == 0 {
				b[0], b[1] = byte(length), 3
			}
			inputs = append(inputs, b)
		}
	}
	for _, b := range inputs {
		original := bytes.Clone(b)
		oldValue, oldStatus := parseUSBIdentityString(b)
		value, status, shape := parseUSBIdentityStringWithFailureShape(b)
		if value != oldValue || status != oldStatus || !bytes.Equal(original, b) || (shape == nil) != (status == "USB_STRING_VERIFIED") {
			t.Fatal("diagnostics changed parser result or input")
		}
		if shape != nil && (shape.ReceivedBytes > 255 || shape.PayloadUTF16Units > 126 || shape.DecodedUTF8Bytes > 378) {
			t.Fatal("unbounded diagnostic payload", shape)
		}
	}
}

func TestUSBDescriptorShapeIsAggregateOnlyAndDoesNotEncodeFailedSerial(t *testing.T) {
	a := "SecretA-0123456789\x00"
	b := "Changed-9876543210\x00"
	first, second := usbIdentityStringFailureShape(identityStringFixture(a)), usbIdentityStringFailureShape(identityStringFixture(b))
	if first != second {
		t.Fatal("same category counts retained exact characters")
	}
	typ := reflect.TypeOf(first)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Type.Kind() != reflect.Int && field.Type.Kind() != reflect.Bool {
			t.Fatal("diagnostic acquired a reversible value/position field", field.Name)
		}
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{a[:len(a)-1], b[:len(b)-1], hex.EncodeToString(identityStringFixture(a)), base64.StdEncoding.EncodeToString(identityStringFixture(a))} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("failed serial leaked")
		}
	}
}
