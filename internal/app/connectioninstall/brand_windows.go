//go:build windows && amd64

package connectioninstall

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/transport/ipadsession"
)

func legacyRoot() (string, error) {
	p, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	return filepath.Join(p, "Suhang iPad USB"), e
}

// An old updater keeps running through this transition and writes its health
// receipt here. Keep that protected journal and certificate at their original
// location, so neither the pinned identity nor its rollback executable is lost.
func maintenanceBase() (string, error) {
	old, e := legacyRoot()
	if e != nil {
		return "", e
	}
	if e = noReparse(filepath.Join(old, "Remote Maintenance")); e == nil {
		return protectedRootAt(old, false)
	} else if !os.IsNotExist(e) {
		return "", e
	}
	return protectedRoot(false)
}

// Migrate settings only. Keep existing user data and updater state in place.
func MigrateBrand() error {
	root, e := protectedRoot(false)
	if e != nil {
		return e
	}
	old, e := legacyRoot()
	if e != nil {
		return e
	}
	if e = noReparse(old); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if _, e = protectedRootAt(old, false); e != nil {
		return e
	}
	pref := filepath.Join(root, "connection-preferences.json")
	if e = noReparse(pref); os.IsNotExist(e) {
		source := filepath.Join(old, "connection-preferences.json")
		if e = noReparse(source); e == nil {
			st, e := os.Stat(source)
			if e != nil {
				return e
			}
			if st.Size() > 128<<10 {
				return fmt.Errorf("legacy settings too large")
			}
			b, e := os.ReadFile(source)
			if e != nil {
				return e
			}
			if _, e = ipadsession.ParsePreferences(b); e != nil {
				return e
			}
			if e = writeRemote(pref, json.RawMessage(b)); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
	} else if e != nil {
		return e
	}
	// User data stays at its existing location. A received installer may be
	// executing inside Received Files, which makes moving its directory fail.
	// Resolve each data folder independently so partial 0.8.0 moves also work.

	return writeRemote(filepath.Join(root, "brand-migration.json"), map[string]any{"product": ProductID, "name": "USB Link", "legacy_updater_preserved": true})
}

// dataRoot retains old data without renaming a directory containing running
// executables or merging/overwriting files. Both roots must be product-owned.
func dataRoot(name string) (string, error) {
	if name != "Shared Files" && name != "Received Files" {
		return "", fmt.Errorf("invalid data folder")
	}
	root, e := protectedRoot(false)
	if e != nil {
		return "", e
	}
	old, e := legacyRoot()
	if e != nil {
		return "", e
	}
	if e = noReparse(filepath.Join(old, name)); os.IsNotExist(e) {
		return root, nil
	} else if e != nil {
		return "", e
	}
	if _, e = protectedRootAt(old, false); e != nil {
		return "", e
	}
	return old, nil
}
