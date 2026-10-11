package fileshare

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeModeDoesNotBypassWindowsAuthenticationThroughLegacyDAVOrSMB(t *testing.T) {
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
	for _, method := range []string{"GET", "PROPFIND", "PUT"} {
		r := httptest.NewRequest(method, "http://10.6.9.1:10690/share/", strings.NewReader("test"))
		r.RemoteAddr = "10.6.9.3:1234"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 410 {
			t.Fatal(method, w.Code)
		}
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
