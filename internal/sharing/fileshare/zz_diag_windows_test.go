//go:build windows

package fileshare

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
)

// TEMPORARY diagnostic; always fails to surface output on CI.
func TestZZDiagDirTimes(t *testing.T) {
	dir := realTemp(t)
	root, err := openShareRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Mkdir("sub", 0755); err != nil {
		t.Fatal(err)
	}
	f, err := root.OpenFile("sub", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cur, e1 := f.Stat()
	at, e2 := root.Lstat("sub")
	t.Errorf("stat: %v %v same=%v", e1, e2, os.SameFile(cur, at))
	for _, access := range []uint32{windows.FILE_WRITE_ATTRIBUTES, windows.DELETE, windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE} {
		h, e := smbReopenHandle(f, access)
		t.Errorf("reopen access=%#x err=%v", access, e)
		if e == nil {
			windows.CloseHandle(h)
		}
	}
	now := time.Unix(1720000000, 0)
	t.Errorf("setdirtimes: %v", smbSetDirectoryTimes(f, &vfs.SetInfoRequest{}, now, now))
	t.Errorf("rootchtimes: %v", root.Chtimes("sub", now, now))
}
