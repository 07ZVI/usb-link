//go:build windows && amd64

package exitrecord

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func protectTestPath(t *testing.T, path string, dir bool) {
	t.Helper()
	sddl := fileSDDL
	if dir {
		sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	}
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		t.Fatal(e)
	}
	owner, _, e := sd.Owner()
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil)
	if e == windows.ERROR_ACCESS_DENIED || e == windows.ERROR_PRIVILEGE_NOT_HELD {
		t.Skip("requires administrator ACL fixture")
	}
	if e != nil {
		t.Fatal(e)
	}
}
func TestProtectedExitRecordAtomicReplaceAndRejectCorruption(t *testing.T) {
	parent := t.TempDir()
	protectTestPath(t, parent, true)
	dir := filepath.Join(parent, "mac-runtime-0.10.52")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	r := fixture()
	if e := Write(dir, r); e != nil {
		t.Fatal(e)
	}
	next := filepath.Join(parent, "mac-runtime-0.10.53")
	if e := os.Mkdir(next, 0700); e != nil {
		t.Fatal(e)
	}
	inherited, found, e := Read(next)
	if e != nil || !found || inherited.Version != r.Version || inherited.Exit.Stage != r.Exit.Stage {
		t.Fatalf("cross-version read failed: %v", e)
	}
	if _, e := os.Stat(filepath.Join(dir, leaf)); !os.IsNotExist(e) {
		t.Fatal("per-runtime copy created")
	}
	r.Exit.Stage = "RESTORE_FAILED"
	if e := Write(dir, r); e != nil {
		t.Fatal(e)
	}
	got, found, e := Read(dir)
	if e != nil || !found || got.Exit.Stage != r.Exit.Stage {
		t.Fatalf("read %v %v", found, e)
	}
	if e = os.WriteFile(filepath.Join(parent, leaf), []byte(`{"core_version":`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = Read(dir); e == nil {
		t.Fatal("partial record accepted")
	}
	if e = Write(dir, fixture()); e == nil {
		t.Fatal("invalid prior record replaced")
	}
}
func TestProtectedExitRecordRejectsLeafRedirection(t *testing.T) {
	parent := t.TempDir()
	protectTestPath(t, parent, true)
	dir := filepath.Join(parent, "mac-runtime-0.10.52")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	other := filepath.Join(parent, "other")
	b, _ := Encode(fixture())
	if e := os.WriteFile(other, b, 0600); e != nil {
		t.Fatal(e)
	}
	protectTestPath(t, other, false)
	if e := os.Link(other, filepath.Join(parent, leaf)); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Read(dir); e == nil {
		t.Fatal("hardlink accepted")
	}
	if e := Write(dir, fixture()); e == nil {
		t.Fatal("hardlink replaced")
	}
}
