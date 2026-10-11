//go:build windows && amd64

package connectioninstall

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/platform/windows/installcleanup"
)

// PrepareDesktop materializes only files from the embedded release payload in
// an administrator-owned, content-addressed directory. Every launch checks all
// files, including runtime DLLs, against the embedded bytes. Extra files fail.
func PrepareDesktop(payload []byte) (string, error) {
	return PrepareDesktopArchive(bytes.NewReader(payload), int64(len(payload)))
}

// PrepareDesktopArchive retains the immutable archive and independently checks
// all installed files against its embedded publisher manifest on every launch.
func PrepareDesktopArchive(reader io.ReaderAt, size int64) (string, error) {
	root, err := protectedRoot(false)
	if err != nil {
		return "", err
	}
	name, err := DesktopDirectoryNameArchive(reader, size)
	if err != nil {
		return "", err
	}
	z, err := zip.NewReader(reader, size)
	if err != nil {
		return "", err
	}
	target := filepath.Join(root, name)
	dir := target
	fresh := false
	if _, err = os.Lstat(target); os.IsNotExist(err) {
		fresh = true
		dir, err = os.MkdirTemp(root, "desktop-stage-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(dir)
	} else if err != nil {
		return "", err
	}
	if err = noReparse(dir); err != nil {
		return "", fmt.Errorf("desktop path redirected")
	}
	if err = prepareIndexedDesktopEntries(z, dir, fresh, noReparse); err != nil {
		return "", err
	}
	if fresh {
		if err = os.Rename(dir, target); err != nil {
			return "", err
		}
	}
	return filepath.Join(target, "USBLink.Desktop.exe"), nil
}

// Enumerate verified, application-owned runtime files for normal uninstall.
// Shared and received user data never enter this list.
func desktopRemovalFiles(dir string) ([]string, error) {
	inventory, err := desktopInventory(dir)
	if err != nil {
		return nil, err
	}
	return installcleanup.Files(dir, "desktop-ownership.json", inventory, 80<<20, cleanupSafePath)
}
