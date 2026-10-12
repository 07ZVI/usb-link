//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Fixed-layout repair restores only the exact accepted publisher bytes. Missing
// legacy residual cleanup uses its separate exact-profile backup verifier; an
// arbitrary name/path cannot authorize adoption or a SYSTEM command change.
func inspectMissingAcceptedInstallation(version string) (InstallationTransaction, bool, error) {
	t, ok, e := readInstallationTransaction()
	if e != nil || !ok {
		return t, false, e
	}
	if t.Phase != InstallComplete || t.Next.Version != version {
		return t, false, nil
	}
	self, e := os.Executable()
	if e != nil {
		return t, false, e
	}
	sum, e := fileHash(self)
	if e != nil {
		return t, false, e
	}
	if sum != t.Next.SHA {
		return t, false, nil
	}
	current, e := CurrentApplication()
	if e != nil {
		return t, false, e
	}
	if VerifyCoreExecutable(current) == nil && verifyReleaseFiles(filepath.Dir(current), t.NextFiles, false) == nil {
		return t, false, nil
	}
	if _, err := os.Lstat(current); err == nil {
		sum, err := fileHash(current)
		if err != nil || sum != t.Next.SHA {
			return t, false, fmt.Errorf("INSTALL_REPAIR_EXISTING_SOURCE_CHANGED")
		}
	} else if !os.IsNotExist(err) {
		return t, false, err
	}
	clean, e := completedUninstallAbsence(t, current)
	if e != nil {
		return t, false, e
	}
	if clean {
		return t, false, nil
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || u.User.Sid.String() != t.OwnerSID || !windows.GetCurrentProcessToken().IsElevated() {
		return t, false, fmt.Errorf("INSTALL_REPAIR_OWNER_CHANGED")
	}
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return t, false, e
	}
	raw, e := coreProtectedRead(filepath.Join(base, "USB Link", "State", coreBindingFile), false, true)
	if e != nil {
		return t, false, e
	}
	b, e := parseCoreBinding(raw)
	if e != nil || b != (CoreServiceBinding{1, ProductID, t.OwnerSID, current, t.Next.SHA}) {
		return t, false, fmt.Errorf("INSTALL_REPAIR_BINDING_CHANGED")
	}
	m, e := mgr.Connect()
	if e != nil {
		return t, false, e
	}
	defer m.Disconnect()
	s, e := m.OpenService(CoreServiceName)
	if e != nil {
		return t, false, e
	}
	defer s.Close()
	if e = coreServiceSecurity(s); e != nil {
		return t, false, e
	}
	config, e := s.Config()
	if e != nil {
		return t, false, e
	}
	args, e := windows.DecomposeCommandLine(config.BinaryPathName)
	if e != nil || validateCoreServiceConfig(current, config.ServiceStartName, config.ServiceType, config.StartType, config.DelayedAutoStart, args) != nil {
		return t, false, fmt.Errorf("INSTALL_REPAIR_SERVICE_CHANGED")
	}
	if e = coreServiceExecutionPolicy(s, config); e != nil {
		return t, false, e
	}
	status, e := s.Query()
	if e == nil && status.State == svc.Running && VerifyCoreExecutable(current) == nil {
		return t, false, nil
	}
	if e != nil || status.State != svc.Stopped || status.ProcessId != 0 {
		return t, false, fmt.Errorf("INSTALL_REPAIR_SERVICE_NOT_STOPPED")
	}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE)
	if e != nil {
		return t, false, e
	}
	defer k.Close()
	for name, want := range map[string]string{"ProductID": ProductID, "DisplayName": "USB Link", "DisplayVersion": version, "Publisher": "USB Link", "InstallLocation": filepath.Dir(current), "DisplayIcon": current} {
		v, typ, e := k.GetStringValue(name)
		if e != nil || typ != registry.SZ || v != want {
			return t, false, fmt.Errorf("INSTALL_REPAIR_REGISTRATION_CHANGED")
		}
	}
	command, _, e := k.GetStringValue("UninstallString")
	args, parse := windows.DecomposeCommandLine(command)
	if e != nil || parse != nil || len(args) != 2 || !strings.EqualFold(args[0], current) || args[1] != "--uninstall" {
		return t, false, fmt.Errorf("INSTALL_REPAIR_UNINSTALL_ACTION_CHANGED")
	}
	return t, true, nil
}
func repairMissingAcceptedInstallation(ops *nativeInstallation, t InstallationTransaction, self string, archive io.ReaderAt, size int64) error {
	// Repeat the complete native check under installation and SCM leases before
	// the first file is written. No service or registry mutation is required.
	fresh, ok, e := inspectMissingAcceptedInstallation(t.Next.Version)
	if e != nil || !ok || fresh.Next != t.Next {
		return fmt.Errorf("INSTALL_REPAIR_STATE_CHANGED: %v", e)
	}
	want, e := plannedInstallationInventory(t.Next, archive, size)
	if e != nil || !installationInventoriesEqual(want, t.NextFiles) {
		return fmt.Errorf("INSTALL_REPAIR_PAYLOAD_CHANGED")
	}
	originalCandidate := ops.candidate
	// Hydrate App directly with the original payload and bounded atomic files.
	// Completed acceptance proves the release; no temporary service is adopted.
	ops.candidate = ops.app
	e = stageInstallationRelease(ops, t, self, archive, size)
	ops.candidate = originalCandidate
	if e != nil {
		return e
	}
	return VerifyCoreExecutable(filepath.Join(ops.app, BinaryName))
}

// Historical completion is retained after uninstall. Prove that all four active
// objects are absent before classifying the same original setup as a new install.
func completedUninstallAbsence(t InstallationTransaction, current string) (bool, error) {
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return false, e
	}
	filePresent := func(path string) (bool, error) {
		_, e := os.Lstat(path)
		if os.IsNotExist(e) {
			return false, nil
		}
		return e == nil, e
	}
	return cleanCompletedUninstall(t.Phase, cleanUninstallProbes{
		Source:  func() (bool, error) { return filePresent(current) },
		Binding: func() (bool, error) { return filePresent(filepath.Join(base, "USB Link", "State", coreBindingFile)) },
		Registration: func() (bool, error) {
			k, e := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE)
			if e == registry.ErrNotExist {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			k.Close()
			return true, nil
		},
		Service: func() (bool, error) {
			m, e := deletedInstallSCM()
			if e != nil {
				return false, e
			}
			defer m.Disconnect()
			s, e := deletedInstallService(m, false)
			if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			s.Close()
			return true, nil
		},
	})
}
