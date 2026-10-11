//go:build windows && amd64

package background

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"log"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/winusb"
	"time"
)

const registryKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SuhangUSBNet`

type ownership struct {
	Product string
	Version string
	Files   map[string]string
}

func Root() (string, error) {
	p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(p, "Suhang USB"), nil
}

func noReparse(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refuse installation through a reparse point")
	}
	return nil
}

// Create a protected directory directly under the OS-known Program Files.
// No LocalAppData binary/DLL is ever launched by the SYSTEM service.
func Prepare(version string, files map[string][]byte) (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	newRoot := false
	if err = os.Mkdir(root, 0700); err != nil && !os.IsExist(err) {
		return "", err
	} else if err == nil {
		newRoot = true
	}
	if !newRoot {
		b, e := os.ReadFile(filepath.Join(root, "product-id.txt"))
		if e != nil || strings.TrimSpace(string(b)) != ProductID {
			return "", fmt.Errorf("preserve unowned application directory")
		}
	}
	if err = noReparse(root); err != nil {
		return "", err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
	if err != nil {
		return "", err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	if err = windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return "", err
	}
	if newRoot {
		if err = os.WriteFile(filepath.Join(root, "product-id.txt"), []byte(ProductID), 0600); err != nil {
			return "", err
		}
	}
	dir := filepath.Join(root, version)
	if _, err = os.Stat(dir); err == nil {
		if err = noReparse(dir); err != nil {
			return "", err
		}
		var owned ownership
		b, err := os.ReadFile(filepath.Join(dir, "ownership.json"))
		if err != nil {
			return "", err
		}
		if json.Unmarshal(b, &owned) != nil || owned.Product != ProductID || owned.Version != version {
			return "", fmt.Errorf("unowned installation directory")
		}
		for name, data := range files {
			sum := sha256.Sum256(data)
			if owned.Files[name] != hex.EncodeToString(sum[:]) {
				return "", fmt.Errorf("same version has different assets; preserve existing files")
			}
			if err = noReparse(filepath.Join(dir, name)); err != nil {
				return "", err
			}
			actual, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return "", err
			}
			if sha256.Sum256(actual) != sum {
				return "", fmt.Errorf("installed asset integrity mismatch")
			}
		}
		return dir, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return "", err
	}
	owned := ownership{Product: ProductID, Version: version, Files: map[string]string{}}
	for name, data := range files {
		if filepath.Base(name) != name || name == "ownership.json" {
			return "", fmt.Errorf("invalid installation asset name")
		}
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		owned.Files[name] = hex.EncodeToString(sum[:])
	}
	b, _ := json.MarshalIndent(owned, "", "  ")
	if err = os.WriteFile(filepath.Join(dir, "ownership.json"), b, 0600); err != nil {
		return "", err
	}
	return dir, nil
}

func ownedService(m *mgr.Mgr) (*mgr.Service, error) {
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return nil, err
	}
	c, err := s.Config()
	if err != nil {
		s.Close()
		return nil, err
	}
	args, err := windows.DecomposeCommandLine(c.BinaryPathName)
	root, rootErr := Root()
	if err != nil || rootErr != nil || len(args) != 2 || args[1] != "--service" || !strings.EqualFold(filepath.Base(args[0]), "Suhang-USB-Setup.exe") || !strings.EqualFold(filepath.Dir(filepath.Dir(args[0])), root) {
		s.Close()
		return nil, fmt.Errorf("service name belongs to an unrecognized binary")
	}
	var marker ownership
	b, err := os.ReadFile(filepath.Join(filepath.Dir(args[0]), "ownership.json"))
	if err != nil || json.Unmarshal(b, &marker) != nil || marker.Product != ProductID {
		s.Close()
		return nil, fmt.Errorf("missing service ownership marker")
	}
	for _, path := range []string{root, filepath.Dir(args[0]), filepath.Join(filepath.Dir(args[0]), "ownership.json"), args[0]} {
		if err = noReparse(path); err != nil {
			s.Close()
			return nil, err
		}
	}
	product, err := os.ReadFile(filepath.Join(root, "product-id.txt"))
	executable, readErr := os.ReadFile(args[0])
	digest := sha256.Sum256(executable)
	if err != nil || readErr != nil || strings.TrimSpace(string(product)) != ProductID || marker.Version != filepath.Base(filepath.Dir(args[0])) || marker.Files[filepath.Base(args[0])] != hex.EncodeToString(digest[:]) {
		s.Close()
		return nil, fmt.Errorf("legacy service executable ownership changed")
	}
	return s, nil
}

func stop(s *mgr.Service) error {
	state, err := s.Query()
	if err != nil {
		return err
	}
	if state.State == svc.Stopped {
		return nil
	}
	if state.State != svc.StopPending {
		if _, err = s.Control(svc.Stop); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		state, err = s.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Stopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("owned service is still cleaning up; files preserved")
}

func Install(dir, version string) (installErr error) {
	// Preserve foreign uninstall entries before making service changes.
	if key, e := registry.OpenKey(registry.LOCAL_MACHINE, registryKey, registry.QUERY_VALUE); e == nil {
		id, _, e := key.GetStringValue("ProductID")
		key.Close()
		if e != nil || id != ProductID {
			return fmt.Errorf("preserve unowned uninstall registry key")
		}
	} else if e != windows.ERROR_FILE_NOT_FOUND {
		return e
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	exe := filepath.Join(dir, "Suhang-USB-Setup.exe")
	created := false
	var previous *mgr.Config
	s, err := ownedService(m)
	if err == nil {
		defer s.Close()
		if err = stop(s); err != nil {
			return err
		}
		c, err := s.Config()
		if err != nil {
			return err
		}
		old := c
		previous = &old
		c.BinaryPathName = windows.ComposeCommandLine([]string{exe, "--service"})
		c.StartType = mgr.StartAutomatic
		c.DelayedAutoStart = true
		if err = s.UpdateConfig(c); err != nil {
			return err
		}
	} else {
		// Only "not found" permits creation. A foreign name is preserved.
		if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return err
		}
		s, err = m.CreateService(ServiceName, exe, mgr.Config{StartType: mgr.StartAutomatic, DelayedAutoStart: true, DisplayName: "隨航 USB 網路", Description: "Suhang USB: background monitor; a new user approval is required for each cable connection."}, "--service")
		if err != nil {
			return err
		}
		created = true
		defer s.Close()
	}
	defer func() {
		if installErr == nil {
			return
		}
		if err := stop(s); err != nil {
			installErr = fmt.Errorf("%w; rollback stop: %v", installErr, err)
			return
		}
		if created {
			if err := s.Delete(); err != nil {
				installErr = fmt.Errorf("%w; rollback service: %v", installErr, err)
			}
		} else if previous != nil {
			if err := s.UpdateConfig(*previous); err != nil {
				installErr = fmt.Errorf("%w; rollback config: %v", installErr, err)
			} else {
				s.Start()
			}
		}
	}()
	k, existing, err := registry.CreateKey(registry.LOCAL_MACHINE, registryKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if existing {
		id, _, e := k.GetStringValue("ProductID")
		if e != nil || id != ProductID {
			return fmt.Errorf("preserve unowned uninstall registry key")
		}
	}
	for name, value := range map[string]string{"DisplayName": "隨航 USB 網路", "DisplayVersion": version, "Publisher": "Suhang", "InstallLocation": dir, "UninstallString": windows.ComposeCommandLine([]string{exe, "--uninstall"}), "ProductID": ProductID} {
		if err = k.SetStringValue(name, value); err != nil {
			return err
		}
	}
	if err = shortcut(exe, false); err != nil {
		return err
	}
	if err = s.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state, err := s.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Running {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("service did not report running; see service.log")
}

func Control(command svc.Cmd) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := ownedService(m)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Control(command)
	return err
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := ownedService(m)
	if err != nil {
		return err
	}
	defer s.Close()
	if err = stop(s); err != nil {
		return err
	}
	config, err := s.Config()
	if err != nil {
		return err
	}
	args, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(args) != 2 {
		return fmt.Errorf("invalid owned service path")
	}
	dir := filepath.Dir(args[0])
	if err = verifyNetworkCleanup(dir); err != nil {
		return err
	}
	if err = shortcut(args[0], true); err != nil {
		return err
	}
	if err = s.Delete(); err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, registryKey, registry.QUERY_VALUE)
	if err == nil {
		id, _, getErr := k.GetStringValue("ProductID")
		k.Close()
		if getErr == nil && id == ProductID {
			if err = registry.DeleteKey(registry.LOCAL_MACHINE, registryKey); err != nil {
				return err
			}
		}
	}
	return removeOwnedFiles()
}

// Suspend only our verified legacy service. Retain its installation and logs:
// unrelated files or driver directories must not gate the new connection.
func SuspendForUnified() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := ownedService(m)
	if err != nil {
		return err
	}
	defer s.Close()
	if err = stop(s); err != nil {
		return err
	}
	c, err := s.Config()
	if err != nil {
		return err
	}
	args, err := windows.DecomposeCommandLine(c.BinaryPathName)
	if err != nil || len(args) != 2 {
		return fmt.Errorf("invalid owned service path")
	}
	if err = verifyNetworkCleanup(filepath.Dir(args[0])); err != nil {
		return err
	}
	verified, err := ownedService(m)
	if err != nil {
		return err
	}
	defer verified.Close()
	fresh, err := verified.Config()
	if err != nil || fresh.BinaryPathName != c.BinaryPathName {
		return fmt.Errorf("owned service changed during suspension")
	}
	fresh.StartType = mgr.StartDisabled
	return verified.UpdateConfig(fresh)
}

func verifyNetworkCleanup(dir string) error {
	if err := noReparse(dir); err != nil {
		return err
	}
	journal := filepath.Join(dir, "owned-session.json")
	if _, err := os.Lstat(journal); os.IsNotExist(err) {
		return nil
	}
	if err := noReparse(journal); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(dir, "owned-session.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state struct {
		GUID  string `json:"guid"`
		Token string `json:"token"`
	}
	if err = json.Unmarshal(b, &state); err != nil {
		return err
	}
	release, err := winusb.OwnRuntime()
	if err != nil {
		return err
	}
	defer release()
	_, cleanup, err := netconfig.Scripts(1, state.GUID, 1500, state.Token)
	if err != nil {
		return err
	}
	files, err := netconfig.FileReceiverRule(state.GUID, state.Token, false)
	if err != nil {
		return err
	}
	adapter, err := netconfig.RecoverAdapter(state.GUID, state.Token)
	if err != nil {
		return err
	}
	var output bytes.Buffer
	logger := log.New(&output, "", 0)
	if err = netconfig.Run(files+cleanup+adapter, logger); err != nil {
		details := output.String()
		if len(details) > 16384 {
			details = details[:16384]
		}
		return fmt.Errorf("legacy network cleanup: %w; %s", err, details)
	}
	script, err := netconfig.VerifyCleanup(state.GUID, state.Token)
	if err != nil {
		return err
	}
	if err = netconfig.Run(script, logger); err != nil {
		details := output.String()
		if len(details) > 16384 {
			details = details[:16384]
		}
		return fmt.Errorf("legacy cleanup verification: %w; %s", err, details)
	}
	return nil
}

// Remove only manifest-owned assets and the fixed logs produced by this tool.
// Running installer/locked files are scheduled for removal at the next reboot.
// Unknown files/directories are preserved and explicitly reported.
func removeOwnedFiles() error {
	root, err := Root()
	if err != nil {
		return err
	}
	if err = noReparse(root); err != nil {
		return err
	}
	marker, err := os.ReadFile(filepath.Join(root, "product-id.txt"))
	if err != nil || strings.TrimSpace(string(marker)) != ProductID {
		return fmt.Errorf("missing application ownership marker")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var files, dirs []string
	archive := filepath.Join(os.Getenv("LOCALAPPDATA"), "Suhang", "USBNet", "Uninstall-"+time.Now().Format("20060102-150405"))
	logs := map[string]bool{"installer.log": true, "usbnet-bridge.log": true, "service.log": true, "service.log.1": true, "usbnet-bridge.log.1": true, "ncm-probe.log": true, "診斷資料.zip": true, "owned-session.json": true}
	for _, entry := range entries {
		if !entry.IsDir() {
			if entry.Name() != "product-id.txt" {
				return fmt.Errorf("unknown application file preserved: %s", entry.Name())
			}
			continue
		}
		dir := filepath.Join(root, entry.Name())
		if err = noReparse(dir); err != nil {
			return err
		}
		var owned ownership
		b, err := os.ReadFile(filepath.Join(dir, "ownership.json"))
		if err != nil || json.Unmarshal(b, &owned) != nil || owned.Product != ProductID || owned.Version != entry.Name() {
			return fmt.Errorf("unowned version directory preserved")
		}
		children, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, child := range children {
			path := filepath.Join(dir, child.Name())
			if err = noReparse(path); err != nil {
				return err
			}
			if child.IsDir() {
				return fmt.Errorf("additional installation directory preserved: %s; export/review it before removal", child.Name())
			}
			_, asset := owned.Files[child.Name()]
			if !asset && !logs[child.Name()] && child.Name() != "ownership.json" {
				return fmt.Errorf("unknown version file preserved: %s", child.Name())
			}
			if asset {
				content, readErr := os.ReadFile(path)
				digest := sha256.Sum256(content)
				if readErr != nil || owned.Files[child.Name()] != hex.EncodeToString(digest[:]) {
					return fmt.Errorf("changed legacy asset preserved: %s", child.Name())
				}
			}
			if logs[child.Name()] {
				if err = os.MkdirAll(filepath.Join(archive, entry.Name()), 0700); err != nil {
					return err
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if err = os.WriteFile(filepath.Join(archive, entry.Name(), child.Name()), data, 0600); err != nil {
					return err
				}
			}
			files = append(files, path)
		}
		dirs = append(dirs, dir)
	}
	files = append(files, filepath.Join(root, "product-id.txt"))
	delayed := false
	for _, path := range files {
		if err = os.Remove(path); err != nil {
			if !os.IsPermission(err) {
				return err
			}
			p, _ := windows.UTF16PtrFromString(path)
			if err = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
				return err
			}
			delayed = true
		}
	}
	dirs = append(dirs, root)
	for _, path := range dirs {
		if delayed {
			p, _ := windows.UTF16PtrFromString(path)
			if err = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
				return err
			}
		} else if err = os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}
