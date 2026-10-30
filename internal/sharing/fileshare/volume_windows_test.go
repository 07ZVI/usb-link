//go:build windows

package fileshare

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestStableVolumePathRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := NewCatalog(nil)
	defer c.Close()
	f, err := c.Add("", dir)
	if err != nil {
		t.Fatal(err)
	}
	path, err := StableVolumePath(dir, f.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if !IsVolumePath(path) {
		t.Fatal(path)
	}
	if err = c.Relocate(f.ID, path); err != nil {
		t.Fatal(err)
	}
	c.Refresh()
	got := c.List()[0]
	if !got.Available || got.Name != f.Name || got.Identity != f.Identity {
		t.Fatalf("lost original folder: %+v", got)
	}
	if !strings.EqualFold(filepath.Clean(DisplayVolumePath(path)), filepath.Clean(dir)) {
		t.Fatal(DisplayVolumePath(path), dir)
	}
	if _, err = c.Add("", dir); err == nil {
		t.Fatal("drive-letter alias added twice")
	}
	if _, err = StableVolumePath(dir, "win:wrong"); err == nil {
		t.Fatal("rebound different identity")
	}
	root := filepath.VolumeName(dir) + `\`
	r := NewCatalog(nil)
	defer r.Close()
	rf, err := r.Add("", root)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := StableVolumePath(root, rf.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if rp != VolumeRoot(rp) {
		t.Fatal("invalid volume root", rp)
	}
	if err = r.Relocate(rf.ID, rp); err != nil {
		t.Fatal(err)
	}
}
