package macconnection

import (
	"path/filepath"
	"suhang/usbnet/internal/dependencies"
)

// Only this owner's protected recovery store is searched. The actual official
// DLL pin, rather than a filename or old bridge identity, authorizes reuse.
func PinnedLegacyWintun(parent string) string {
	return pinnedLegacyWintun(parent, dependencies.WintunAMD64SHA256)
}

func pinnedLegacyWintun(parent, want string) string {
	if !safeRuntimeDirectory(parent) {
		return ""
	}
	names, err := recoveryRuntimeNames(parent)
	if err != nil {
		return ""
	}
	for _, name := range names {
		dir := filepath.Join(parent, name)
		if !safeRuntimeDirectory(dir) {
			continue
		}
		path := filepath.Join(dir, "wintun.dll")
		if actual, err := runtimeAssetHash(path); err == nil && actual == want {
			return path
		}
	}
	return ""
}
