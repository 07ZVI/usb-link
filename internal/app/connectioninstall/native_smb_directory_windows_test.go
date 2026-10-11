//go:build windows && amd64

package connectioninstall

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func openSMBTestPin(t *testing.T, path string) windows.Handle {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	return h
}

func TestSMBDirectoryReopenKeepsOriginalAfterRename(t *testing.T) {
	base := t.TempDir()
	path, moved := filepath.Join(base, "selected"), filepath.Join(base, "moved")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	pin := openSMBTestPin(t, path)
	sd, identity, err := smbRootSecurity(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	h, err := reopenSMBDirectory(pin, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := verifySMBACLHandle(h, identity, sd.String()); err != nil {
		t.Fatalf("reopened original must remain bound after path replacement: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, restoreSMBDACLInfo(sd), nil, nil, acl, nil); err != nil {
		t.Fatalf("same DACL write to test directory: %v", err)
	}
	got, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || !sameSMBRootDACL(got.String(), sd.String()) {
		t.Fatalf("permission readback differs: %v", err)
	}
}

func TestSMBDirectoryReopenVolumeRootReadOnly(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + `\`
	pin := openSMBTestPin(t, root)
	sd, identity, err := smbRootSecurity(root)
	if err != nil {
		t.Fatal(err)
	}
	h, err := reopenSMBDirectory(pin, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := verifySMBACLHandle(h, identity, sd.String()); err != nil {
		t.Fatal(err)
	}
}

func TestSMBDirectoryReopenRejectsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	h, err := reopenSMBDirectory(openSMBTestPin(t, path), windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err == nil {
		windows.CloseHandle(h)
		t.Fatal("directory open must reject an ordinary file")
	}
}
