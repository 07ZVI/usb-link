//go:build windows && amd64

// Legacy uninstall/SCM cleanup for the previously shipped 0.8.139/0.9.3
// layout after the entire program root was deleted. This removes exact stopped
// residuals after a durable backup; it never adopts an unbound service.
package connectioninstall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type DeletedInstallSnapshot struct {
	Product              string            `json:"product"`
	CapturedUTC          string            `json:"captured_utc"`
	Registration         map[string]string `json:"registration,omitempty"`
	RegistrationSecurity string            `json:"registration_security,omitempty"`
	Service              *mgr.Config       `json:"service,omitempty"`
	ServiceSecurity      string            `json:"service_security,omitempty"`
}

// Fixed-layout receipts belong to their own recovery coordinator. Legacy
// cleanup must never bypass a retained binding or installation transaction.
func noModernInstallationRecords() error {
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return e
	}
	state := filepath.Join(data, "USB Link", "State")
	if _, e := os.Lstat(state); !os.IsNotExist(e) {
		if e != nil {
			return e
		}
		if _, e := protectedRootAt(state, false); e != nil {
			return e
		}
	}
	for _, name := range []string{coreBindingFile, coreTransitionFile, InstallationTransactionName} {
		if _, e := os.Lstat(filepath.Join(state, name)); !os.IsNotExist(e) {
			return fmt.Errorf("REPAIR_MODERN_INSTALLATION_RECORD_PRESENT_OR_UNREADABLE: %s", name)
		}
	}
	return nil
}

func missingInstallRoot() (string, error) {
	root, e := Root()
	if e != nil {
		return "", e
	}
	if e = noModernInstallationRecords(); e != nil {
		return "", e
	}
	// The actual Program Files parent must not be a redirected directory.
	if e = noReparse(filepath.Dir(root)); e != nil {
		return "", e
	}
	if _, e = os.Lstat(root); !os.IsNotExist(e) {
		return "", fmt.Errorf("REPAIR_PROGRAM_DIRECTORY_PRESENT_OR_UNREADABLE")
	}
	return root, nil
}

func deletedRegistration(root, old string) (map[string]string, string, error) {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.READ)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return nil, "", nil
	}
	if e != nil {
		return nil, "", e
	}
	defer k.Close()
	info, e := k.Stat()
	if e != nil || info.SubKeyCount != 0 || info.ValueCount != 9 {
		return nil, "", fmt.Errorf("REPAIR_REGISTRATION_SHAPE_CHANGED")
	}
	exe := filepath.Join(root, old, BinaryName)
	want := map[string]string{"ProductID": ProductID, "DisplayName": "USB Link", "Publisher": "USB Link", "DisplayVersion": old, "InstallLocation": filepath.Dir(exe), "DisplayIcon": exe}
	got := make(map[string]string)
	for name, value := range want {
		v, typ, err := k.GetStringValue(name)
		if err != nil || typ != registry.SZ || v != value {
			return nil, "", fmt.Errorf("REPAIR_REGISTRATION_CHANGED: %s", name)
		}
		got[name] = v
	}
	cmd, typ, e := k.GetStringValue("UninstallString")
	args, parse := windows.DecomposeCommandLine(cmd)
	if e != nil || typ != registry.SZ || parse != nil || !reflect.DeepEqual(args, []string{exe, "--uninstall"}) {
		return nil, "", fmt.Errorf("REPAIR_UNINSTALL_ACTION_CHANGED")
	}
	got["UninstallString"] = cmd
	for _, name := range []string{"NoModify", "NoRepair"} {
		v, typ, err := k.GetIntegerValue(name)
		if err != nil || typ != registry.DWORD || v != 1 {
			return nil, "", fmt.Errorf("REPAIR_REGISTRATION_CHANGED: %s", name)
		}
		got[name] = "1"
	}
	sd, e := windows.GetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil {
		return nil, "", fmt.Errorf("REPAIR_REGISTRY_SECURITY_UNPROVEN")
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return nil, "", fmt.Errorf("REPAIR_REGISTRY_OWNER_UNPROVEN")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount > 32 {
		return nil, "", fmt.Errorf("REPAIR_REGISTRY_ACL_UNPROVEN")
	}
	elevatedSID := ""
	token := windows.GetCurrentProcessToken()
	session, sessionError := shareTokenDWORD(token, windows.TokenSessionId)
	if token.IsElevated() && sessionError == nil && session != 0 {
		user, e := token.GetTokenUser()
		if e != nil {
			return nil, "", e
		}
		elevatedSID = user.User.Sid.String()
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil || a == nil || a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || a.Header.AceSize < 20 || a.Header.AceSize > 68 {
			return nil, "", fmt.Errorf("REPAIR_REGISTRY_ACL_UNPROVEN")
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		count := *(*byte)(unsafe.Add(unsafe.Pointer(sid), 1))
		if uint32(a.Header.AceSize) != 16+4*uint32(count) || !sid.IsValid() {
			return nil, "", fmt.Errorf("REPAIR_REGISTRY_ACL_UNPROVEN")
		}
		if a.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if registryAccessCanMutate(uint32(a.Mask)) && !trustedDeletedRegistryWriter(sid.String(), elevatedSID) {
			return nil, "", fmt.Errorf("REPAIR_REGISTRY_FOREIGN_WRITE: SID=%s, access=0x%08x, flags=0x%02x", sid.String(), uint32(a.Mask), a.Header.AceFlags)
		}
	}
	return got, sd.String(), nil
}

func deletedService(s *mgr.Service, root, old string) (*mgr.Config, string, error) {
	if e := coreServiceSecurity(s); e != nil {
		return nil, "", e
	}
	c, e := s.Config()
	if e != nil {
		return nil, "", e
	}
	args, parse := windows.DecomposeCommandLine(c.BinaryPathName)
	if parse != nil || validateCoreServiceConfig(filepath.Join(root, old, BinaryName), c.ServiceStartName, c.ServiceType, c.StartType, c.DelayedAutoStart, args) != nil || c.DisplayName != "USB Link" || c.Description != "USB Link core: owned USB networking, local UI IPC; no interactive Session0 UI." || c.Password != "" {
		return nil, "", fmt.Errorf("REPAIR_SERVICE_CONFIG_CHANGED")
	}
	if e = coreServiceExecutionPolicy(s, c); e != nil {
		return nil, "", e
	}
	status, e := s.Query()
	if e != nil || status.State != svc.Stopped || status.ProcessId != 0 {
		return nil, "", fmt.Errorf("REPAIR_SERVICE_NOT_STOPPED")
	}
	sd, e := windows.GetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return nil, "", e
	}
	return &c, sd.String(), nil
}

func noDeletedInstallProcesses() error {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	p := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for e = windows.Process32First(h, &p); e == nil; e = windows.Process32Next(h, &p) {
		if p.ProcessID == uint32(os.Getpid()) {
			continue
		} // The external installer itself is expected.
		switch strings.ToLower(windows.UTF16ToString(p.ExeFile[:])) {
		case "usb-link.exe", "usblink.desktop.exe", "suhang-usbnet.exe", "suhang-ipad-usb.exe":
			return fmt.Errorf("REPAIR_PROGRAM_STILL_RUNNING")
		}
	}
	if e != windows.ERROR_NO_MORE_FILES {
		return e
	}
	return nil
}

// Read-only gate before preparing components. Repair repeats every proof while
// holding the lifecycle mutex immediately before its own mutations.
func InspectReportedDeletedInstallation() error {
	root, e := missingInstallRoot()
	if e != nil {
		return e
	}
	if e = noDeletedInstallProcesses(); e != nil {
		return e
	}
	if _, _, e = deletedRegistration(root, "0.8.139"); e != nil {
		return e
	}
	m, e := deletedInstallSCM()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := deletedInstallService(m, false)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return nil
	}
	if e != nil {
		return e
	}
	defer s.Close()
	_, _, e = deletedService(s, root, "0.9.3")
	return e
}

// Operator recovery of this specific deleted installation. No caller can
// supply arbitrary names/versions, and missing product receipts are not adopted.
// No stop, config update, account/share, driver or USB restoration is performed.
func RepairReportedDeletedInstallation() (string, error) {
	return RepairDeletedInstallation(context.Background())
}

func RepairDeletedInstallation(ctx context.Context) (backup string, err error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if e := pendingInstallationRemoval(); e != nil {
		return "", e
	}
	token := windows.GetCurrentProcessToken()
	session, e := shareTokenDWORD(token, windows.TokenSessionId)
	if !token.IsElevated() || e != nil || session == 0 {
		return "", fmt.Errorf("REPAIR_INTERACTIVE_ADMIN_REQUIRED")
	}
	unlock, e := coreLifecycleLock()
	if e != nil {
		return "", e
	}
	defer func() {
		if e := unlock(); err == nil {
			err = e
		}
	}()
	root, e := missingInstallRoot()
	if e != nil {
		return "", e
	}
	if e = noDeletedInstallProcesses(); e != nil {
		return "", e
	}
	reg, regSD, e := deletedRegistration(root, "0.8.139")
	if e != nil {
		return "", e
	}
	m, e := deletedInstallSCM()
	if e != nil {
		return "", e
	}
	defer m.Disconnect()
	s, e := deletedInstallService(m, true)
	if e != nil && e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return "", e
	}
	if s != nil {
		defer func() {
			if s != nil {
				s.Close()
			}
		}()
	}
	var config *mgr.Config
	var serviceSD string
	if s != nil {
		config, serviceSD, e = deletedService(s, root, "0.9.3")
		if e != nil {
			return "", e
		}
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	// An interrupted run may have removed one or both exact old objects.
	if s == nil && reg == nil {
		return "", PreflightLocalInstallation()
	}

	return runDeletedInstallRemoval(ctx, deletedInstallRemoval{
		Backup: func() (string, error) {
			deps, e := DependencyDirectory()
			if e != nil {
				return "", e
			}
			parent, e := protectedRootAt(filepath.Join(filepath.Dir(deps), "DeletedInstallRecovery"), true)
			if e != nil {
				return "", e
			}
			dir, e := protectedRootAt(filepath.Join(parent, time.Now().UTC().Format("20060102T150405.000000000Z")), true)
			if e != nil {
				return "", e
			}
			snapshot := DeletedInstallSnapshot{ProductID, time.Now().UTC().Format(time.RFC3339Nano), reg, regSD, config, serviceSD}
			b, e := json.MarshalIndent(snapshot, "", "  ")
			if e != nil {
				return "", e
			}
			backup := filepath.Join(dir, "before.json")
			f, e := os.OpenFile(backup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return "", e
			}
			_, e = f.Write(b)
			if e == nil {
				e = f.Sync()
			}
			closed := f.Close()
			if e != nil {
				return backup, e
			}
			if closed != nil {
				return backup, closed
			}
			readback, e := coreProtectedReadBounded(backup, false, true, 16384)
			if e != nil || string(readback) != string(b) {
				return backup, fmt.Errorf("REPAIR_BACKUP_READBACK_FAILED")
			}
			return backup, nil
		},
		Recheck: func() error {
			if _, e := missingInstallRoot(); e != nil {
				return e
			}
			if e := noDeletedInstallProcesses(); e != nil {
				return e
			}
			newReg, newSD, e := deletedRegistration(root, "0.8.139")
			if e != nil || !reflect.DeepEqual(newReg, reg) || newSD != regSD {
				return fmt.Errorf("REPAIR_REGISTRATION_CHANGED_AFTER_BACKUP")
			}
			// Inspect a newly opened handle too: an object appearing after an absent
			// snapshot cannot be silently ignored or removed by a stale plan.
			check, e := deletedInstallService(m, false)
			if config == nil {
				if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
					return nil
				}
				if check != nil {
					check.Close()
				}
				return fmt.Errorf("REPAIR_SERVICE_APPEARED_AFTER_BACKUP")
			}
			if e != nil {
				return e
			}
			defer check.Close()
			c, sd, e := deletedService(check, root, "0.9.3")
			if e != nil || !reflect.DeepEqual(c, config) || sd != serviceSD {
				return fmt.Errorf("REPAIR_SERVICE_CHANGED_AFTER_BACKUP")
			}
			return nil
		},
		Service: func() error {
			if s == nil {
				return nil
			}
			c, sd, e := deletedService(s, root, "0.9.3")
			if e != nil || !reflect.DeepEqual(c, config) || sd != serviceSD {
				return fmt.Errorf("REPAIR_SERVICE_CHANGED_BEFORE_DELETE")
			}
			if e := s.Delete(); e != nil {
				return e
			}
			closed := s.Close()
			s = nil
			if closed != nil {
				return closed
			}
			deadline := time.Now().Add(15 * time.Second)
			for {
				check, e := deletedInstallService(m, false)
				if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
					return nil
				}
				if check != nil {
					check.Close()
				}
				if (e != nil && e != windows.ERROR_SERVICE_MARKED_FOR_DELETE) || time.Now().After(deadline) {
					return fmt.Errorf("REPAIR_SERVICE_DELETE_PENDING: 请关闭服务管理窗口，必要时重启 Windows 后再安装。 %v", e)
				}
				time.Sleep(200 * time.Millisecond)
			}
		},
		Registration: func() error {
			if reg == nil {
				return nil
			}
			if _, e := missingInstallRoot(); e != nil {
				return e
			}
			newReg, newSD, e := deletedRegistration(root, "0.8.139")
			if e != nil || !reflect.DeepEqual(newReg, reg) || newSD != regSD {
				return fmt.Errorf("REPAIR_REGISTRATION_CHANGED_BEFORE_DELETE")
			}
			check, e := deletedInstallService(m, false)
			if check != nil {
				check.Close()
			}
			if e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
				return fmt.Errorf("REPAIR_SERVICE_PRESENT_BEFORE_REGISTRATION_DELETE")
			}
			return registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey)
		},
		VerifyClean: PreflightLocalInstallation,
	})
}

func deletedInstallSCM() (*mgr.Mgr, error) {
	h, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return nil, e
	}
	return &mgr.Mgr{Handle: h}, nil
}
func deletedInstallService(m *mgr.Mgr, remove bool) (*mgr.Service, error) {
	access := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS | windows.READ_CONTROL)
	if remove {
		access |= windows.DELETE
	}
	h, e := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(CoreServiceName), access)
	if e != nil {
		return nil, e
	}
	return &mgr.Service{Name: CoreServiceName, Handle: h}, nil
}

// The initial preflight may recognize only the exact reviewed legacy state.
// Normal installs, authenticated fixed-layout repair and interrupted updates
// retain their existing gates. Mutation repeats the legacy proof under a lease.
func PlanLocalInstallationForSetup(version string) (cleanup bool, err error) {
	normal := PreflightLocalInstallationForSetup(version)
	if normal == nil {
		return false, nil
	}
	if e := pendingInstallationRemoval(); e != nil {
		return false, e
	}
	if e := InspectReportedDeletedInstallation(); e != nil {
		return false, fmt.Errorf("%w\n旧安装记录无法自动清理：%v", normal, e)
	}
	return true, nil
}
