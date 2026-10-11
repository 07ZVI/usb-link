package ipadsession

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This policy accepts an actual descriptor serial and product description,
// never a Windows instance/location suffix. USB identifiers remain forgeable.
func ValidUSBDescriptorIdentity(serial, product string) bool {
	if !stableUSBSerial.MatchString(serial) || !utf8.ValidString(product) || len(product) > 128 || strings.TrimSpace(product) != product || !(product == "iPad" || strings.HasPrefix(product, "iPad ")) {
		return false
	}
	return !strings.ContainsFunc(product, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar })
}

func USBDescriptorSerialDigest(serial string) string {
	if !stableUSBSerial.MatchString(serial) {
		return ""
	}
	i := sha256.Sum256([]byte("Suhang USB descriptor serial v2\x00" + serial))
	return hex.EncodeToString(i[:])
}

// Domain separation prevents an old PnP instance grant from acquiring stronger
// descriptor provenance, even when its apparent serial happens to match.
func USBDescriptorGrant(serial, product, pid, layout string) USBDeviceGrant {
	if pid != "12AB" || layout == "" || !ValidUSBDescriptorIdentity(serial, product) {
		return USBDeviceGrant{}
	}
	i := sha256.Sum256([]byte("Suhang USB descriptor identity v2\x00" + pid + "\x00" + serial + "\x00" + product))
	f := sha256.Sum256([]byte("Suhang USB descriptor layout v2\x00" + pid + "\x00" + layout + "\x00" + product))
	return USBDeviceGrant{hex.EncodeToString(i[:]), hex.EncodeToString(f[:]), pid}
}
