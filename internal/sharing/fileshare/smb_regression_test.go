package fileshare

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"sync/atomic"
	"testing"
	"time"
)

func fileFixture(t *testing.T) (*Catalog, *smbCatalog, Folder) {
	t.Helper()
	c := NewCatalog(nil)
	t.Cleanup(c.Close)
	folder, e := c.Add("", realTemp(t))
	if e != nil {
		t.Fatal(e)
	}
	state := &State{}
	state.Enabled.Store(true)
	s := &Server{catalog: c, State: state, Guard: func() bool { return true }}
	return c, &smbCatalog{s: s, ctx: context.Background()}, folder
}
func openRegressionFile(t *testing.T, b *smbCatalog, name string) *smbFile {
	t.Helper()
	f, e := b.Open(context.Background(), vfs.OpenOptions{Path: name, Disposition: vfs.DispositionOpen, DesiredAccess: 0x10000000})
	if e != nil {
		t.Fatal(e)
	}
	h := f.(*smbFile)
	t.Cleanup(func() { h.Close(context.Background()) })
	return h
}

func TestSMBRenameThenDeleteKeepsNewFileAtOldPath(t *testing.T) {
	_, b, folder := fileFixture(t)
	old := filepath.Join(folder.Path, "old.txt")
	if e := os.WriteFile(old, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	h := openRegressionFile(t, b, folder.Name+"/old.txt")
	if e := h.Rename(context.Background(), folder.Name+"/new.txt", false); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(old, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := h.Remove(context.Background()); e != nil {
		t.Fatal(e)
	}
	h.Close(context.Background())
	if got, e := os.ReadFile(old); e != nil || string(got) != "replacement" {
		t.Fatal("replacement deleted", string(got), e)
	}
	if _, e := os.Stat(filepath.Join(folder.Path, "new.txt")); !os.IsNotExist(e) {
		t.Fatal("renamed file survived", e)
	}
}

func TestSMBExternallyReplacedPathCannotBeDeletedOrRenamed(t *testing.T) {
	_, b, folder := fileFixture(t)
	old := filepath.Join(folder.Path, "old.txt")
	moved := filepath.Join(folder.Path, "moved.txt")
	if e := os.WriteFile(old, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	h := openRegressionFile(t, b, folder.Name+"/old.txt")
	if e := os.Rename(old, moved); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(old, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := h.Remove(context.Background()); !errors.Is(e, os.ErrPermission) {
		t.Fatal("replacement delete accepted", e)
	}
	if e := h.Rename(context.Background(), folder.Name+"/new.txt", false); !errors.Is(e, os.ErrPermission) {
		t.Fatal("replacement rename accepted", e)
	}
	if got, e := os.ReadFile(old); e != nil || string(got) != "replacement" {
		t.Fatal(string(got), e)
	}
}

func TestSMBCaseOnlyRenameAndLiteralBracketEnumeration(t *testing.T) {
	_, b, folder := fileFixture(t)
	old := filepath.Join(folder.Path, "Photo [1].JPG")
	if e := os.WriteFile(old, []byte("photo"), 0600); e != nil {
		t.Fatal(e)
	}
	h := openRegressionFile(t, b, folder.Name+"/Photo [1].JPG")
	if e := h.Rename(context.Background(), folder.Name+"/Photo [1].jpg", false); e != nil {
		t.Fatal(e)
	}
	dir := openRegressionFile(t, b, folder.Name)
	var names []string
	for info, e := range dir.Enumerate(context.Background(), "Photo [1].jpg") {
		if e != nil {
			t.Fatal(e)
		}
		names = append(names, info.Name)
	}
	if len(names) != 1 || names[0] != "Photo [1].jpg" {
		t.Fatal(names)
	}
}

func TestSMBCrossRootRenameReportsDifferentDevice(t *testing.T) {
	c, b, folder := fileFixture(t)
	other, e := c.Add("", realTemp(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(folder.Path, "data"), []byte("source"), 0600); e != nil {
		t.Fatal(e)
	}
	h := openRegressionFile(t, b, folder.Name+"/data")
	if e := h.Rename(context.Background(), other.Name+"/data", false); !errors.Is(e, vfs.ErrNotSameDevice) {
		t.Fatal(e)
	}
	if got, e := os.ReadFile(filepath.Join(folder.Path, "data")); e != nil || string(got) != "source" {
		t.Fatal(string(got), e)
	}
}

func TestSMBDirectoryMetadataDoesNotModifyReplacement(t *testing.T) {
	_, b, folder := fileFixture(t)
	dir := filepath.Join(folder.Path, "dir")
	moved := filepath.Join(folder.Path, "moved")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	h := openRegressionFile(t, b, folder.Name+"/dir")
	if e := os.Rename(dir, moved); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	stamp := time.Unix(1720000000, 0)
	if e := h.SetInfo(context.Background(), &vfs.SetInfoRequest{LastWriteTime: &stamp}); !errors.Is(e, os.ErrPermission) {
		t.Fatal("replacement metadata changed", e)
	}
}

func TestCatalogRetryRecoversOfflineRootButRejectsReplacement(t *testing.T) {
	c := NewCatalog(nil)
	defer c.Close()
	parent := realTemp(t)
	root := filepath.Join(parent, "drive")
	f, e := c.Restore("123456789012345678901234", root)
	if e != nil || f.Available {
		t.Fatal(f, e)
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	c.Refresh()
	if !c.List()[0].Available {
		t.Fatal("reconnected drive remained unavailable")
	}
	allowed := c.allowed(f.ID)
	if e := os.Rename(root, root+"-old"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	c.Refresh()
	if c.List()[0].Available || allowed() {
		t.Fatal("pinned root rebound to replacement")
	}
}

func TestCatalogReleasesOfflineRootAndRecoversOnlySameIdentity(t *testing.T) {
	c := NewCatalog(nil)
	defer c.Close()
	base := realTemp(t)
	root := filepath.Join(base, "drive")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	folder, e := c.Add("", root)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(root, root+"-offline"); e != nil {
		t.Fatal(e)
	}
	c.Refresh()
	if c.folders[folder.ID].root != nil || c.List()[0].Available {
		t.Fatal("offline root handle retained")
	}
	if e = os.Rename(root+"-offline", root); e != nil {
		t.Fatal(e)
	}
	c.Refresh()
	if !c.List()[0].Available || c.List()[0].Identity != folder.Identity {
		t.Fatal("same drive did not recover")
	}
	if e = os.Rename(root, root+"-original"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	c.Refresh()
	if c.List()[0].Available || c.folders[folder.ID].root != nil {
		t.Fatal("replacement root accepted")
	}
	restarted := NewCatalog(nil)
	defer restarted.Close()
	f, e := restarted.RestoreIdentity(folder.ID, root, folder.Identity)
	if e != nil || f.Available {
		t.Fatal("replacement accepted after restart", f, e)
	}
}

func TestNativeMetadataCatalogDoesNotKeepDriveHandle(t *testing.T) {
	c := NewMetadataCatalog(nil)
	defer c.Close()
	f, e := c.Add("", realTemp(t))
	if e != nil {
		t.Fatal(e)
	}
	c.Refresh()
	if c.folders[f.ID].root != nil || !c.List()[0].Available || c.List()[0].Identity == "" {
		t.Fatal("native catalog retained a handle or lost identity")
	}
}

func TestCatalogSlowRefreshDoesNotBlockListOrResurrectRemoval(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var block atomic.Bool
	c := NewCatalog(func(fn func() error) error {
		if block.Load() {
			close(entered)
			<-release
		}
		return fn()
	})
	defer c.Close()
	f, e := c.Add("", realTemp(t))
	if e != nil {
		t.Fatal(e)
	}
	block.Store(true)
	done := make(chan struct{})
	go func() { c.Refresh(); close(done) }()
	<-entered
	listed := make(chan struct{})
	go func() { c.List(); c.Remove(f.ID); close(listed) }()
	select {
	case <-listed:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("slow drive blocked list/removal")
	}
	close(release)
	<-done
	if len(c.List()) != 0 {
		t.Fatal("refresh resurrected removed entry")
	}
}
