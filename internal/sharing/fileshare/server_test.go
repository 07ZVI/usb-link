package fileshare

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRootConfinementAndWindowsNames(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0600)
	os.Symlink(outside, filepath.Join(dir, "escape"))
	r, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	f := rootFS{r}
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

func TestHardLinkCannotReadOrTruncateOutsideFile(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	os.WriteFile(outside, []byte("preserve"), 0600)
	if e := os.Link(outside, filepath.Join(dir, "alias.txt")); e != nil {
		t.Fatal(e)
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	fs := rootFS{r}
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
