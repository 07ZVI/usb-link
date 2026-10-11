//go:build windows && amd64

package netconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// Opt-in native fixture; cross-compilation is not execution evidence. The
// artifact must be the fixed official DLL hash, never downloaded by this test.
func TestWintunNativeOfficialArtifact(t *testing.T) {
	path := os.Getenv("USBLINK_TEST_OFFICIAL_WINTUN_DLL")
	if path == "" {
		t.Skip("requires local official DLL on native Windows")
	}
	lease, err := PinVerifiedWintunNative(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWintunNativeUnsignedFileRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wintun.dll")
	if err := os.WriteFile(path, []byte("unsigned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if lease, err := PinVerifiedWintunNative(path, nil); err == nil {
		_ = lease.Close()
		t.Fatal("accepted nonofficial unsigned DLL")
	}
}
