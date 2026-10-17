//go:build usblink_local_remote

package remoteupdate

import (
	"crypto/ed25519"
	"encoding/hex"
)

// LocalPublisherHex is a developer public key injected only into local builds.
// A missing or malformed key never falls back to release signing authority.
var LocalPublisherHex string

func PublisherKey() ed25519.PublicKey {
	b, err := hex.DecodeString(LocalPublisherHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}
