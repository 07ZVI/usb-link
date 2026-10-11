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
	r := InstallationInspection{InspectedAt: time.Now().UTC().Format(time.RFC3339)}
	problem := func(label string, err error) { r.Errors = append(r.Errors, fmt.Sprintf("%s：%v", label, err)) }
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
	}
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		problem("安装凭据", e)
	} else {
		r.BindingPresent = exists("安装凭据", filepath.Join(data, "USB Link", "State", coreBindingFile))
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
	status, e := s.Query()
	if e != nil {
		problem("服务状态", e)
	} else {
		r.ServicePID = status.ProcessId
		r.ServiceState = map[svc.State]string{svc.Stopped: "已停止", svc.StartPending: "正在启动", svc.StopPending: "正在停止", svc.Running: "正在运行", svc.ContinuePending: "正在恢复", svc.PausePending: "正在暂停", svc.Paused: "已暂停"}[status.State]
		if r.ServiceState == "" {
			r.ServiceState = fmt.Sprintf("未知状态 %d", status.State)
		}
	}
	config, e := s.Config()
	if e != nil {
		problem("服务程序", e)
	} else if args, ae := windows.DecomposeCommandLine(config.BinaryPathName); ae != nil || len(args) == 0 {
		problem("服务程序", fmt.Errorf("服务命令格式无法识别"))
	} else {
		r.ServiceExecutable = args[0]
		r.ServiceExecutablePresent = exists("服务程序", args[0])
	}
	return r
}
