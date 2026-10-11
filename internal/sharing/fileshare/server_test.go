package fileshare

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDAVLifecycleAndUSBConsent(t *testing.T) {
	state := &State{}
	s, e := New(t.TempDir(), "10.6.9.2", state, func() bool { return true })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	call := func(method, p, body string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, "http://10.6.9.1:10690"+p, strings.NewReader(body))
		q.RemoteAddr = "10.6.9.2:50000"
		q.Header.Set("Depth", "1")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, q)
		return w
	}
	if w := call("PUT", "/share/hello.txt", "test"); w.Code != 403 {
		t.Fatal("default exposed", w.Code)
	}
	state.Enabled.Store(true)
	if w := call("MKCOL", "/share/測試", ""); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("PUT", "/share/測試/hello.txt", "hello USB"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", "/share/測試/hello.txt", ""); w.Code != 200 || w.Body.String() != "hello USB" {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("PROPFIND", "/share/測試", ""); w.Code != 207 || !bytes.Contains(w.Body.Bytes(), []byte("hello.txt")) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("DELETE", "/share/測試/hello.txt", ""); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	q := httptest.NewRequest("GET", "http://10.6.9.1:10690/share/", nil)
	q.RemoteAddr = "192.168.1.9:3"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, q)
	if w.Code != 403 {
		t.Fatal("LAN peer admitted")
	}
}
func TestRootConfinementAndWindowsNames(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0600)
	os.Symlink(outside, filepath.Join(dir, "escape"))
	s, e := New(dir, "10.6.9.2", &State{}, func() bool { return true })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	f := rootFS{s.root}
	for _, n := range []string{"../secret", "escape/secret", "hello:stream", "CON", "a\\b", "a. "} {
		if h, e := f.OpenFile(context.Background(), n, os.O_RDONLY, 0); e == nil {
			h.Close()
			t.Fatal("escape or reserved path", n)
		}
	}
	if e = f.RemoveAll(context.Background(), "/"); e == nil {
		t.Fatal("root deleted")
	}
}

func TestFinderMethodsAndRevocation(t *testing.T) {
	state := &State{}
	state.Enabled.Store(true)
	valid := true
	server, e := New(t.TempDir(), "10.6.9.2", state, func() bool { return valid })
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	call := func(method, name, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://10.6.9.1:10690/share/"+name, strings.NewReader(body))
		r.RemoteAddr = "10.6.9.2:50001"
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		return w
	}
	if w := call("OPTIONS", "", "", nil); w.Code != 200 || w.Header().Get("DAV") == "" {
		t.Fatalf("OPTIONS: %d", w.Code)
	}
	if w := call("PUT", "original.txt", "shared", nil); w.Code != 201 {
		t.Fatal(w.Code)
	}
	if w := call("COPY", "original.txt", "", map[string]string{"Destination": "http://10.6.9.1:10690/share/copy.txt"}); w.Code != 201 {
		t.Fatal("COPY", w.Code, w.Body)
	}
	if w := call("MOVE", "copy.txt", "", map[string]string{"Destination": "http://10.6.9.1:10690/share/renamed.txt"}); w.Code != 201 {
		t.Fatal("MOVE", w.Code, w.Body)
	}
	lock := call("LOCK", "renamed.txt", `<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>Finder test</D:owner></D:lockinfo>`, map[string]string{"Content-Type": "application/xml", "Timeout": "Second-60"})
	if lock.Code != 200 || lock.Header().Get("Lock-Token") == "" {
		t.Fatal("LOCK", lock.Code, lock.Body)
	}
	if w := call("PUT", "renamed.txt", "blocked", nil); w.Code != 423 {
		t.Fatal("lock not enforced", w.Code)
	}
	if w := call("UNLOCK", "renamed.txt", "", map[string]string{"Lock-Token": lock.Header().Get("Lock-Token")}); w.Code != 204 {
		t.Fatal("UNLOCK", w.Code, w.Body)
	}
	if w := call("GET", "renamed.txt", "", nil); w.Body.String() != "shared" {
		t.Fatal("copy changed")
	}
	state.Enabled.Store(false)
	if w := call("GET", "renamed.txt", "", nil); w.Code != 403 {
		t.Fatal("disabled still accessible")
	}
	state.Enabled.Store(true)
	valid = false
	if w := call("GET", "renamed.txt", "", nil); w.Code != 403 {
		t.Fatal("disconnected accessible")
	}
}

func TestHardLinkCannotReadOrTruncateOutsideFile(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	os.WriteFile(outside, []byte("preserve"), 0600)
	if e := os.Link(outside, filepath.Join(dir, "alias.txt")); e != nil {
		t.Fatal(e)
	}
	server, e := New(dir, "10.6.9.2", &State{}, func() bool { return true })
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	fs := rootFS{server.root}
	for _, flags := range []int{os.O_RDONLY, os.O_WRONLY | os.O_TRUNC} {
		if f, e := fs.OpenFile(context.Background(), "alias.txt", flags, 0600); e == nil {
			f.Close()
			t.Fatal("hard link admitted")
		}
	}
	b, e := os.ReadFile(outside)
	if e != nil || string(b) != "preserve" {
		t.Fatal("outside content altered")
	}
}
