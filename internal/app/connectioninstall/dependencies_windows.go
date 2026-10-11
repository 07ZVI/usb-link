//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/dependencies"
)

func DependencyDirectory() (string, error) {
	// Different component preparations may run together, but first creation of
	// the common directory/marker must finish before another process reads it.
	release, e := acquireUpgradeJobMutex(`Global\USBLinkDependencyDirectory-v1`, 10000)
	if e != nil {
		return "", e
	}
	defer release()
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return "", e
	}
	root, e := protectedRootAt(filepath.Join(base, "USB Link"), true)
	if e != nil {
		return "", e
	}
	return protectedRootAt(filepath.Join(root, "Dependencies"), true)
}

// A normal offline BAT or another installer may have supplied these original
// archives. Readiness never depends on which program copied them. The manager
// checks the compiled catalog hash and official signature before using bytes.
func LocalDependencyArchive(a dependencies.Asset) string {
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e == nil {
		u, e := url.Parse(a.URL)
		if e == nil {
			path := filepath.Join(base, "USB-Link Components", filepath.Base(u.Path))
			if st, e := os.Lstat(path); e == nil && st.Mode().IsRegular() && st.Size() <= a.MaxBytes {
				return path
			}
		}
	}
	return LegacyOfflineDependencyArchive(a)
}

// Compatibility import for verified offline ZIPs supplied to an older version.
// This never starts a receiver, grants access or executes a received file. Only
// catalog-pinned .NET/Wintun archives can be selected; source data is preserved.
func LegacyOfflineDependencyArchive(a dependencies.Asset) string {
	if a.ID != "dotnet" && a.ID != "wintun" {
		return ""
	}
	u, err := url.Parse(a.URL)
	if err != nil || !strings.HasSuffix(u.Path, ".zip") {
		return ""
	}
	base := filepath.Base(u.Path)
	root, err := dataRoot("Received Files")
	if err != nil {
		return ""
	}
	dir := filepath.Join(root, "Received Files")
	if noReparse(dir) != nil {
		return ""
	}
	sd, err := windows.SecurityDescriptorFromString(installACL)
	if err != nil {
		return ""
	}
	actual, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || !sameACL(actual, sd) {
		return ""
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 4096 {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), "-"+base) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if noReparse(path) != nil {
			continue
		}
		return path
	}
	return ""
}
func VerifyDependencyPath(path string) error {
	root, e := DependencyDirectory()
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(root, path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("DEPENDENCY_OUTSIDE_OWNED_ROOT")
	}
	for p := path; p != root; p = filepath.Dir(p) {
		if noReparse(p) != nil {
			return fmt.Errorf("DEPENDENCY_PATH_REDIRECTED")
		}
	}
	return nil
}

// Only the marked private dependency tree belongs to this product. System-wide
// Apple software, installed drivers and shared runtimes are never removed here.
func RemoveDependencies() error {
	dir, e := DependencyDirectory()
	if e != nil {
		return e
	}
	if _, e = os.Stat(filepath.Join(dir, "internet-journal.json")); e == nil {
		return fmt.Errorf("DEPENDENCY_GATEWAY_RECOVERY_PENDING")
	}
	if e = filepath.WalkDir(dir, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return VerifyDependencyPath(path)
	}); e != nil {
		return e
	}
	return os.RemoveAll(dir)
}
