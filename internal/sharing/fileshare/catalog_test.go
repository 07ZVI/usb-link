package fileshare

import (
	"context"
	"io"
	"os"
	"path/filepath"
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
	f := catalogFS{c}
	ctx := context.Background()
	write := func(path, body string) {
		h, err := f.OpenFile(ctx, path, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		h.Close()
	}
	read := func(path string) string {
		h, err := f.OpenFile(ctx, path, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		data, err := io.ReadAll(h)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	write(a.ID+"/hello", "one")
	write(b.ID+"/hello", "two")
	if read(a.ID+"/hello") != "one" || read(b.ID+"/hello") != "two" {
		t.Fatal("mounts mixed")
	}
	if e = f.Rename(context.Background(), a.ID+"/hello", b.ID+"/stolen"); e == nil {
		t.Fatal("cross-root rename allowed")
	}
	if e = f.RemoveAll(context.Background(), a.ID); e == nil {
		t.Fatal("mount root deleted")
	}
	allowed := c.allowed(a.ID + "/hello")
	if e = c.Remove(a.ID); e != nil {
		t.Fatal(e)
	}
	if allowed() {
		t.Fatal("inflight access not revoked")
	}
	if h, err := f.OpenFile(ctx, a.ID+"/hello", os.O_RDONLY, 0); err == nil {
		h.Close()
		t.Fatal("removed share accessible")
	}
	if data, e := os.ReadFile(filepath.Join(aDir, "hello")); e != nil || string(data) != "one" {
		t.Fatal("local data removed", e)
	}
	if read(b.ID+"/hello") != "two" {
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
	if c.allowed(b.ID + "/data")() {
		t.Fatal("unavailable share exported")
	}
	if _, e = c.Path(a.ID); e != nil {
		t.Fatal("other share broken", e)
	}
	if e = c.Remove(b.ID); e != nil {
		t.Fatal("cannot remove unavailable share", e)
	}
}
