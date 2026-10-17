//go:build !usblink_local_remote

package remoteupdate

import (
	"crypto/ed25519"
	"encoding/hex"
)

// Publisher trust root. Private key is never bundled in an installer.
func PublisherKey() ed25519.PublicKey {
	b, _ := hex.DecodeString("11da9212cea6d243aca58d297b930d85fc0d87de268a0cef00ff12602dba0272")
	return ed25519.PublicKey(b)
}
