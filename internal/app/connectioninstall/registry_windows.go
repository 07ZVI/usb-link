//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
)

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SuhangIPadUSB`

func ownedRegistration() error {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return nil
	}
	if e != nil {
		return e
	}
	defer k.Close()
	p, _, e := k.GetStringValue("ProductID")
	if e != nil || p != ProductID {
		return fmt.Errorf("foreign uninstall entry")
	}
	cmd, _, e := k.GetStringValue("UninstallString")
	args, err := windows.DecomposeCommandLine(cmd)
	if e == nil && err == nil && len(args) == 2 && args[1] == "--uninstall" {
		if _, missing := os.Lstat(args[0]); os.IsNotExist(missing) {
			return fmt.Errorf("INSTALL_FILES_DELETED: 程式檔案已刪除，但 Windows 安裝登錄仍在。請先檢查 USB Link 殘留服務與安裝登錄，再重新安裝；沒有覆寫現有登錄。")
		}
	}
	if e != nil || err != nil || len(args) != 2 || args[1] != "--uninstall" || Verify(args[0]) != nil {
		return fmt.Errorf("changed uninstall action")
	}
	return nil
}
func Register(path, version string) error {
	if Verify(path) != nil || ownedRegistration() != nil {
		return fmt.Errorf("installation registration ownership failed")
	}
	k, _, e := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer k.Close()
	for n, v := range map[string]string{"ProductID": ProductID, "DisplayName": "USB Link", "DisplayVersion": version, "Publisher": "USB Link", "InstallLocation": filepath.Dir(path), "DisplayIcon": path, "UninstallString": windows.ComposeCommandLine([]string{path, "--uninstall"})} {
		if e = k.SetStringValue(n, v); e != nil {
			return e
		}
	}
	k.SetDWordValue("NoModify", 1)
	k.SetDWordValue("NoRepair", 1)
	return nil
}
func RemoveInstalled(path string) (bool, error) {
	if Verify(path) != nil || ownedRegistration() != nil {
		return false, fmt.Errorf("uninstall ownership failed")
	}
	if e := RemoveCoreService(); e != nil {
		return false, e
	}
	return removeInstalledFiles(path)
}

// The uninstall coordinator calls this while retaining the same stopped-core
// lifecycle lease through all original restoration and exact SCM deletion.
// It never acquires that lease again or removes a newly observed binding.
func removeInstalledFiles(path string) (bool, error) {
	if Verify(path) != nil || ownedRegistration() != nil {
		return false, fmt.Errorf("uninstall ownership failed")
	}
	if e := SetNativeSMB(false); e != nil {
		return false, e
	}
	if e := SetNativeSMBGuest(false); e != nil {
		return false, e
	}
	if e := removeSMBAccount(); e != nil {
		return false, e
	}
	if e := RemoveRemoteAccess(); e != nil {
		return false, e
	}
	if e := UpdateShortcut(path, true); e != nil {
		return false, e
	}
	if e := SetStartup(false, path); e != nil {
		return false, e
	}
	root, e := protectedRoot(false)
	if e != nil {
		return false, e
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return false, e
	}
	// Validate every version before deleting anything. Unknown files are retained.
	var files, dirs []string
	modernDesktop := filepath.Join(root, "Desktop")
	if _, err := os.Lstat(modernDesktop); err == nil {
		if _, err = protectedRootAt(modernDesktop, false); err != nil {
			return false, err
		}
		children, err := os.ReadDir(modernDesktop)
		if err != nil {
			return false, err
		}
		for _, child := range children {
			if child.Name() == "product-id.txt" {
				continue
			}
			if !child.IsDir() || !versionPattern.MatchString(child.Name()) {
				return false, fmt.Errorf("unknown desktop contents preserved")
			}
			dir := filepath.Join(modernDesktop, child.Name())
			owned, err := desktopRemovalFiles(dir)
			if err != nil {
				return false, err
			}
			files = append(files, owned...)
			dirs = append(dirs, dir)
		}
		files = append(files, filepath.Join(modernDesktop, "product-id.txt"))
		dirs = append(dirs, modernDesktop)
	} else if !os.IsNotExist(err) {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "desktop-") && len(entry.Name()) == len("desktop-")+24 {
			dir := filepath.Join(root, entry.Name())
			owned, err := desktopRemovalFiles(dir)
			if err != nil {
				return false, err
			}
			files = append(files, owned...)
			dirs = append(dirs, dir)
			continue
		}
		if !entry.IsDir() || !versionPattern.MatchString(entry.Name()) {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		r, e := readReceipt(dir)
		if e != nil {
			return false, e
		}
		names, e := os.ReadDir(dir)
		if e != nil || len(names) != 2 {
			return false, fmt.Errorf("unknown version contents preserved")
		}
		exe := filepath.Join(dir, BinaryName)
		sum, e := fileHash(exe)
		if e != nil || sum != r.SHA {
			return false, fmt.Errorf("changed executable preserved")
		}
		files = append(files, exe, filepath.Join(dir, "ownership.json"))
		dirs = append(dirs, dir)
	}
	pref := filepath.Join(root, "connection-preferences.json")
	if _, e = os.Stat(pref); e == nil {
		if noReparse(pref) != nil {
			return false, fmt.Errorf("unsafe preferences")
		}
		b, e := os.ReadFile(pref)
		if e != nil {
			return false, e
		}
		if _, e = ipadsession.ParsePreferences(b); e != nil {
			return false, e
		}
		files = append(files, pref)
	}
	reboot := false
	remove := func(p string) error {
		if e := os.Remove(p); e == nil || os.IsNotExist(e) {
			return nil
		}
		v, _ := windows.UTF16PtrFromString(p)
		if e := windows.MoveFileEx(v, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); e != nil {
			return e
		}
		reboot = true
		return nil
	}
	for _, p := range files {
		if e = remove(p); e != nil {
			return reboot, e
		}
	}
	for _, p := range dirs {
		if e = remove(p); e != nil {
			return reboot, e
		}
	}
	if e = registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey); e != nil && e != windows.ERROR_FILE_NOT_FOUND {
		return reboot, e
	}
	// Keep the root marker when unknown data remains, so a later install does
	// not take over unrecognized contents. No recursive directory deletion.
	remaining, _ := os.ReadDir(root)
	onlyMarker := len(remaining) == 1 && strings.EqualFold(remaining[0].Name(), "product-id.txt")
	if onlyMarker && !reboot {
		if e = os.Remove(filepath.Join(root, "product-id.txt")); e != nil {
			return reboot, e
		}
		os.Remove(root)
	}
	return reboot, nil
}
