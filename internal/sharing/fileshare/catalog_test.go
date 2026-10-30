package fileshare

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogAddRemoveKeepsLocalData(t *testing.T) {
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
	if e = os.WriteFile(filepath.Join(aDir, "hello"), []byte("one"), 0600); e != nil {
		t.Fatal(e)
	}
	if p, e := c.Path(a.ID); e != nil || p != aDir {
		t.Fatal(p, e)
	}
	if e = c.Remove(a.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Path(a.ID); e == nil {
		t.Fatal("removed share still resolves")
	}
	if data, e := os.ReadFile(filepath.Join(aDir, "hello")); e != nil || string(data) != "one" {
		t.Fatal("local data removed", e)
	}
	if _, e = c.Path(b.ID); e != nil {
		t.Fatal("other folder broken", e)
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
func TestCatalogUsesUserForEveryFilesystemProbe(t *testing.T) {
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
	if _, e := c.Add("", realTemp(t)); e != nil {
		t.Fatal(e)
	}
	allowed = false
	if _, e := c.Add("", realTemp(t)); e == nil {
		t.Fatal("elevated probe")
	}
	if calls != 2 {
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
	if _, e = c.Path(b.ID); e == nil {
		t.Fatal("unavailable share resolves")
	}
	if _, e = c.Path(a.ID); e != nil {
		t.Fatal("other share broken", e)
	}
	if e = c.Remove(b.ID); e != nil {
		t.Fatal("cannot remove unavailable share", e)
	}
}

func TestRelocationRejectsDifferentDirectoryWithoutChangingSelection(t *testing.T) {
	c := NewCatalog(nil)
	defer c.Close()
	folder, err := c.Add("", realTemp(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Relocate(folder.ID, realTemp(t)); err == nil {
		t.Fatal("different folder accepted")
	}
	got := c.List()[0]
	if got.Path != folder.Path || got.Identity != folder.Identity || !got.Available {
		t.Fatal("failed relocation changed selection", got)
	}
	if err = c.Relocate(folder.ID, folder.Path); err != nil {
		t.Fatal(err)
	}
	c.Refresh()
	if got = c.List()[0]; !got.Available || got.ID != folder.ID || got.Name != folder.Name {
		t.Fatal(got)
	}
}
