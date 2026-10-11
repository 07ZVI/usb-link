package fileshare

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogMountIsolationAndRevocation(t *testing.T) {
	c := NewCatalog(nil)
	defer c.Close()
	aDir, bDir := realTemp(t), realTemp(t)
	a, e := c.Add("", aDir)
	if e != nil {
		t.Fatal(e)
	}
	b, e := c.Add("", bDir)
	if e != nil {
		t.Fatal(e)
	}
	state := &State{}
	state.Enabled.Store(true)
	s, e := NewMulti(c, "10.6.9.2", state, func() bool { return true })
	if e != nil {
		t.Fatal(e)
	}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://10.6.9.1:10690/share/"+path, strings.NewReader(body))
		r.RemoteAddr = "10.6.9.2:5000"
		r.Header.Set("Depth", "1")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := call("PUT", a.ID+"/hello", "one"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("PUT", b.ID+"/hello", "two"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", a.ID+"/hello", ""); w.Code != 200 || w.Body.String() != "one" {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", b.ID+"/hello", ""); w.Code != 200 || w.Body.String() != "two" {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("PROPFIND", "", ""); w.Code != 207 || !strings.Contains(w.Body.String(), a.ID) || !strings.Contains(w.Body.String(), b.ID) {
		t.Fatal(w.Code, w.Body.String())
	}
	f := catalogFS{c}
	if e = f.Rename(context.Background(), a.ID+"/hello", b.ID+"/stolen"); e == nil {
		t.Fatal("cross-root rename allowed")
	}
	if e = f.RemoveAll(context.Background(), a.ID); e == nil {
		t.Fatal("mount root deleted")
	}
	allowed := c.allowed("/share/" + a.ID + "/hello")
	if e = c.Remove(a.ID); e != nil {
		t.Fatal(e)
	}
	if allowed() {
		t.Fatal("inflight access not revoked")
	}
	if w := call("GET", a.ID+"/hello", ""); w.Code == 200 {
		t.Fatal("removed share accessible")
	}
	if data, e := os.ReadFile(filepath.Join(aDir, "hello")); e != nil || string(data) != "one" {
		t.Fatal("local data removed", e)
	}
	if w := call("GET", b.ID+"/hello", ""); w.Code != 200 {
		t.Fatal("other mount broken")
	}
}
func TestCatalogRejectsRedirectedRootAndDuplicate(t *testing.T) {
	c := NewCatalog(nil)
	defer c.Close()
	dir := realTemp(t)
	if _, e := c.Add("", dir); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Add("", dir); e == nil {
		t.Fatal("duplicate")
	}
	symlink := filepath.Join(t.TempDir(), "alias")
	if e := os.Symlink(dir, symlink); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Add("", symlink); e == nil {
		t.Fatal("redirected root")
	}
	if _, e := c.Add("../escape", t.TempDir()); e == nil {
		t.Fatal("invalid id")
	}
}
func TestCatalogUsesUserForEveryFilesystemMutation(t *testing.T) {
	allowed := true
	calls := 0
	c := NewCatalog(func(f func() error) error {
		calls++
		if !allowed {
			return os.ErrPermission
		}
		return f()
	})
	defer c.Close()
	a, e := c.Add("", realTemp(t))
	if e != nil {
		t.Fatal(e)
	}
	allowed = false
	f := catalogFS{c}
	if _, e = f.OpenFile(context.Background(), a.ID+"/new", os.O_CREATE|os.O_WRONLY, 0600); e == nil {
		t.Fatal("elevated creation")
	}
	if e = f.Mkdir(context.Background(), a.ID+"/directory", 0700); e == nil {
		t.Fatal("elevated mkdir")
	}
	if calls != 3 {
		t.Fatal(calls)
	}
}

func realTemp(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestUnavailableFolderDoesNotBreakOtherShares(t *testing.T) {
	c := NewCatalog(nil)
	defer c.Close()
	a, e := c.Add("", realTemp(t))
	if e != nil {
		t.Fatal(e)
	}
	missing := filepath.Join(realTemp(t), "unplugged")
	b, e := c.Restore("bbbbbbbbbbbbbbbbbbbbbbbb", missing)
	if e != nil || b.Available {
		t.Fatal(b, e)
	}
	if len(c.List()) != 2 {
		t.Fatal("missing item hidden")
	}
	if c.allowed("/share/" + b.ID + "/data")() {
		t.Fatal("unavailable share exported")
	}
	if _, e = c.Path(a.ID); e != nil {
		t.Fatal("other share broken", e)
	}
	if e = c.Remove(b.ID); e != nil {
		t.Fatal("cannot remove unavailable share", e)
	}
}
