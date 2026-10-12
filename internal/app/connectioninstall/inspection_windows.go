//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// InspectInstallation deliberately avoids all protected-directory, transaction,
// ownership and dependency helpers: several of those create or migrate state.
// SCM handles request only connect, query-config and query-status rights.
func InspectInstallation() InstallationInspection {
	r := InstallationInspection{InspectedAt: time.Now().UTC().Format(time.RFC3339), InspectionReadOnly: true, Checks: map[string]string{}}
	problem := func(label string, err error) { r.Errors = append(r.Errors, fmt.Sprintf("%s：%v", label, err)) }
	check := func(label string, err error) {
		r.Checks[label] = "passed"
		if err != nil {
			r.Checks[label] = err.Error()
			problem(label, err)
		}
	}
	check("pendingRebootRemoval", pendingInstallationRemoval())
	integrations, integrationError := inspectInstallationIntegrations()
	r.Integrations = integrations
	check("startupAndShortcuts", integrationError)
	exists := func(label, path string) *bool {
		// Do not follow remote paths from stale/malformed registration values.
		if !filepath.IsAbs(path) || len(filepath.VolumeName(path)) != 2 || strings.HasPrefix(path, `\\`) {
			problem(label, fmt.Errorf("不是本地绝对路径"))
			return nil
		}
		_, e := os.Stat(path)
		if e != nil && !os.IsNotExist(e) {
			problem(label, e)
			return nil
		}
		yes := e == nil
		return &yes
	}
	root, e := Root()
	if e != nil {
		problem("程序目录", e)
	} else {
		r.ProgramDirectory = root
		r.ProgramDirectoryPresent = exists("程序目录", root)
		r.LegacyBindingPresent = exists("旧版安装凭据", filepath.Join(root, coreBindingFile))
		if r.ProgramDirectoryPresent != nil && *r.ProgramDirectoryPresent {
			_, err := protectedRootAt(root, false)
			check("programDirectoryProtection", err)
		}
	}
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		problem("安装凭据", e)
	} else {
		r.BindingPresent = exists("安装凭据", filepath.Join(data, "USB Link", "State", coreBindingFile))
		for _, name := range []string{"", "Dependencies", "State", "Updates"} {
			path := filepath.Join(data, "USB Link", name)
			if present := exists("目录权限", path); present != nil && *present {
				_, err := protectedRootAt(path, false)
				check("dataDirectoryProtection:"+name, err)
			}
		}
		t, present, err := readInstallationTransaction()
		check("transactionRead", err)
		if err == nil {
			r.Transaction = map[string]any{"present": present}
			if present {
				r.Transaction["phase"] = t.Phase
				r.Transaction["version"] = t.Next.Version
				r.Transaction["nextFiles"] = len(t.NextFiles)
				r.Transaction["previousFiles"] = len(t.PreviousFiles)
			}
		}
	}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e == registry.ErrNotExist {
		v := false
		r.RegistrationPresent = &v
	} else if e != nil {
		problem("卸载登记", e)
	} else {
		defer k.Close()
		v := true
		r.RegistrationPresent = &v
		// Open a separate read-control handle so an ACL-query denial does not hide
		// the registration values that were otherwise readable.
		securityKey, securityError := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, windows.READ_CONTROL|registry.WOW64_64KEY)
		if securityError != nil {
			problem("卸载登记权限", securityError)
		} else {
			sd, e := windows.GetSecurityInfo(windows.Handle(securityKey), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			securityKey.Close()
			if e != nil || sd == nil {
				problem("卸载登记权限", fmt.Errorf("无法读取安全描述符：%v", e))
			} else {
				r.RegistrationSecurity = sd.String()
			}
		}

		r.RegisteredVersion, _, e = k.GetStringValue("DisplayVersion")
		if e != nil {
			problem("登记版本", e)
		}
		command, _, e := k.GetStringValue("UninstallString")
		if e != nil {
			problem("登记程序", e)
		} else if args, ae := windows.DecomposeCommandLine(command); ae != nil || len(args) != 2 || args[1] != "--uninstall" {
			problem("登记程序", fmt.Errorf("卸载命令格式无法识别"))
		} else {
			r.RegisteredExecutable = args[0]
			r.RegisteredExecutablePresent = exists("登记程序", args[0])
		}
	}
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		problem("服务管理器", e)
		return r
	}
	defer windows.CloseServiceHandle(scm)
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(CoreServiceName), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		v := false
		r.ServicePresent = &v
		return r
	}
	if e != nil {
		problem("核心服务", e)
		return r
	}
	s := &mgr.Service{Name: CoreServiceName, Handle: h}
	defer s.Close()
	v := true
	r.ServicePresent = &v
	securityHandle, securityError := windows.OpenService(scm, windows.StringToUTF16Ptr(CoreServiceName), windows.READ_CONTROL)
	if securityError != nil {
		problem("核心服务权限", securityError)
	} else {
		sd, e := windows.GetSecurityInfo(securityHandle, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		windows.CloseServiceHandle(securityHandle)
		if e != nil || sd == nil {
			problem("核心服务权限", fmt.Errorf("无法读取安全描述符：%v", e))
		} else {
			r.ServiceSecurity = sd.String()
		}
	}
	status, e := s.Query()
	if e != nil {
		problem("服务状态", e)
	} else {
		r.ServicePID = status.ProcessId
		r.ServiceStatus = map[string]uint32{"state": uint32(status.State), "pid": status.ProcessId, "win32ExitCode": status.Win32ExitCode, "serviceExitCode": status.ServiceSpecificExitCode, "checkpoint": status.CheckPoint, "waitHint": status.WaitHint}
		r.ServiceState = map[svc.State]string{svc.Stopped: "已停止", svc.StartPending: "正在启动", svc.StopPending: "正在停止", svc.Running: "正在运行", svc.ContinuePending: "正在恢复", svc.PausePending: "正在暂停", svc.Paused: "已暂停"}[status.State]
		if r.ServiceState == "" {
			r.ServiceState = fmt.Sprintf("未知状态 %d", status.State)
		}
	}
	config, e := s.Config()
	if e != nil {
		problem("服务程序", e)
	} else {
		r.ServiceConfiguration = map[string]any{"binaryPathName": config.BinaryPathName, "serviceStartName": config.ServiceStartName, "serviceType": config.ServiceType, "startType": config.StartType, "delayedAutoStart": config.DelayedAutoStart, "displayName": config.DisplayName, "description": config.Description, "errorControl": config.ErrorControl, "sidType": config.SidType, "tagId": config.TagId, "loadOrderGroup": config.LoadOrderGroup, "dependencies": config.Dependencies}
		if args, ae := windows.DecomposeCommandLine(config.BinaryPathName); ae != nil || len(args) == 0 {
			problem("服务程序", fmt.Errorf("服务命令格式无法识别"))
		} else {
			r.ServiceExecutable = args[0]
			r.ServiceExecutablePresent = exists("服务程序", args[0])
		}
	}
	r.ServiceRecovery = map[string]any{}
	actions, err := s.RecoveryActions()
	check("serviceRecoveryActions", err)
	if err == nil {
		r.ServiceRecovery["actions"] = actions
	}
	command, err := s.RecoveryCommand()
	check("serviceRecoveryCommand", err)
	if err == nil {
		r.ServiceRecovery["command"] = command
	}
	message, err := s.RebootMessage()
	check("serviceRebootMessage", err)
	if err == nil {
		r.ServiceRecovery["rebootMessage"] = message
	}
	flag, err := s.RecoveryActionsOnNonCrashFailures()
	check("serviceRecoveryNonCrash", err)
	if err == nil {
		r.ServiceRecovery["nonCrash"] = flag
	}
	return r
}
