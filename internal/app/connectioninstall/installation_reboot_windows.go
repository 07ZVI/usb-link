//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"strings"
)

// Delayed uninstall deletion addresses the same fixed App paths. A reinstall
// must wait for that reboot, otherwise Windows would delete the new release.
func pendingInstallationRemoval() error {
	key, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if e != nil {
		return e
	}
	defer key.Close()
	values, _, e := key.GetStringsValue("PendingFileRenameOperations")
	if e == windows.ERROR_FILE_NOT_FOUND {
		return nil
	}
	if e != nil {
		return e
	}
	root, e := Root()
	if e != nil {
		return e
	}
	old, e := legacyRoot()
	if e != nil {
		return e
	}
	for _, value := range values {
		p := strings.TrimPrefix(strings.TrimPrefix(value, "!"), `\??\`)
		for _, base := range []string{root, old} {
			if strings.EqualFold(p, base) || strings.HasPrefix(strings.ToLower(p), strings.ToLower(base+string(filepath.Separator))) {
				return fmt.Errorf("INSTALL_REBOOT_REQUIRED: 上一次卸載的檔案正在等待 Windows 重新啟動後刪除；請重啟後再安裝，避免新版本被待刪除工作移除。")
			}
		}
	}
	return nil
}
