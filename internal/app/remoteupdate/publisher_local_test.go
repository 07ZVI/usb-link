//go:build usblink_local_remote

package remoteupdate

import (
	"bytes"
	"strings"
	"testing"
)

func TestLocalPublisherHasNoReleaseFallback(t *testing.T) {
	old := LocalPublisherHex
	defer func() { LocalPublisherHex = old }()
	for _, value := range []string{"", "00", strings.Repeat("z", 64)} {
		LocalPublisherHex = value
		if PublisherKey() != nil {
			t.Fatal("invalid local key accepted")
		}
	}
	LocalPublisherHex = strings.Repeat("01", 32)
	if !bytes.Equal(PublisherKey(), bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("wrong local key")
	}
}
