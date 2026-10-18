//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"suhang/usbnet/internal/platform/windows/wincom"
)

// Uses only a temp .lnk; no real startup tasks, product folders or registration.
func TestNativeInstallationShortcutReadOnlyContract(t *testing.T) {
	// The shell reports the long form of the temp directory's 8.3 short name.
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(dir, "source.exe")
	path := filepath.Join(dir, "USB Link.lnk")
	if e := os.WriteFile(target, bytes.Repeat([]byte("fixture"), 512), 0600); e != nil {
		t.Fatal(e)
	}
	e = wincom.WithApartment(func() error {
		shell, e := wincom.Create("{72C24DD5-D70A-438B-8A42-98424B88AFB8}")
		if e != nil {
			return e
		}
		defer shell.Close()
		source := func(p string) (string, error) {
			if !strings.EqualFold(p, target) {
				return "", errors.New("wrong target")
			}
			return "verified", nil
		}
		if _, exists, e := inspectInstallationShortcutWithSource(shell, path, source); e != nil || exists {
			t.Fatalf("absent shortcut %v %v", exists, e)
		}
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("query created shortcut", e)
		}
		link, e := nativeObject(shell, "CreateShortcut", true, wincom.String(path))
		if e != nil {
			return e
		}
		defer link.Close()
		if e = link.Put("TargetPath", wincom.String(target)); e != nil {
			return e
		}
		if e = link.Put("Arguments", wincom.String("")); e != nil {
			return e
		}
		v, e := link.Call("Save")
		v.Clear()
		if e != nil {
			return e
		}
		before, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		got, exists, e := inspectInstallationShortcutWithSource(shell, path, source)
		if e != nil {
			return e
		}
		if !exists || got.State != "verified" || !bytes.Equal(got.Content, before) {
			t.Fatal("native shortcut observation differs")
		}
		after, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if !bytes.Equal(before, after) {
			t.Fatal("query changed shortcut")
		}
		if e = link.Put("Arguments", wincom.String("--foreign")); e != nil {
			return e
		}
		v, e = link.Call("Save")
		v.Clear()
		if e != nil {
			return e
		}
		if _, _, e = inspectInstallationShortcutWithSource(shell, path, source); e == nil {
			t.Fatal("foreign action accepted")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
