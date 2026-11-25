//go:build windows && amd64

package openssh

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func elevatedKeyTest(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires elevated Windows token; temporary files only")
	}
}

func TestWindowsKeyFileSaveAndReadback(t *testing.T) {
	elevatedKeyTest(t)
	path := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	s := Status{Path: path, Shared: true}
	want := []byte(testKey(t, 9) + " Windows fixture\r\n")
	if err := withKeyFile(s, true, func(before []byte, save func([]byte) error) error {
		if len(before) != 0 {
			t.Fatal("new file not empty")
		}
		return save(want)
	}); err != nil {
		t.Fatal(err)
	}
	if err := withKeyFile(s, false, func(actual []byte, _ func([]byte) error) error {
		if !bytes.Equal(actual, want) {
			t.Fatal("readback mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.bak"))
	if len(matches) != 0 {
		t.Fatal("successful write retained recovery files")
	}
	p, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(p, windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal(e)
	}
	owner, _, e := sd.Owner()
	if e != nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Fatal("unexpected file owner", e)
	}
	dacl, _, e := sd.DACL()
	if e != nil || dacl.AceCount != 2 {
		t.Fatal("shared key ACL must contain only SYSTEM and Administrators", e)
	}
}

func TestWindowsKeyFileRefusesLinksAndConcurrentWrite(t *testing.T) {
	elevatedKeyTest(t)
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	path := filepath.Join(dir, "authorized_keys")
	if e := os.WriteFile(original, []byte("untouched"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(original, path); e != nil {
		t.Fatal(e)
	}
	called := false
	if e := withKeyFile(Status{Path: path, Shared: true}, true, func(_ []byte, _ func([]byte) error) error { called = true; return nil }); e == nil || called {
		t.Fatal("hard link accepted")
	}
	data, _ := os.ReadFile(original)
	if string(data) != "untouched" {
		t.Fatal("hard link target modified")
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(testKey(t, 10)+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := withKeyFile(Status{Path: path, Shared: true}, true, func(_ []byte, _ func([]byte) error) error {
		other, e := os.OpenFile(path, os.O_WRONLY, 0600)
		if e == nil {
			other.Close()
			t.Fatal("concurrent writer was admitted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "linked-dir")
	if e := os.Symlink(dir, link); e != nil {
		t.Skip("directory symlink unavailable", e)
	}
	if e := withKeyFile(Status{Path: filepath.Join(link, "authorized_keys"), Shared: true}, true, func(_ []byte, _ func([]byte) error) error { t.Fatal("junction/symlink reached callback"); return nil }); e == nil {
		t.Fatal("linked parent accepted")
	}
}
