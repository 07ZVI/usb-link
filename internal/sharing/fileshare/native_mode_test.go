package fileshare

import (
	"context"
	"path/filepath"
	"testing"
)

func TestNativeModeDoesNotBypassWindowsAuthenticationThroughCompatibilitySMB(t *testing.T) {
	var state State
	state.Native.Store(true)
	state.Enabled.Store(true)
	c := NewCatalog(nil)
	defer c.Close()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.Add("", dir)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewMulti(c, "10.6.9.3", &state, func() bool { return true })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.smbEngine != nil || s.smbAllowed(context.Background()) {
		t.Fatal("embedded unauthenticated SMB still available")
	}
}

func TestNativeURLUsesStandardPortAndKeepsLegacyURLWhenModeIsOff(t *testing.T) {
	old := USB.Native.Load()
	t.Cleanup(func() { USB.Native.Store(old) })
	USB.Native.Store(true)
	if SMBConnectURL() != "smb://10.6.9.1" {
		t.Fatal(SMBConnectURL())
	}
	USB.Native.Store(false)
	if SMBConnectURL() != SMBURL {
		t.Fatal(SMBConnectURL())
	}
}
