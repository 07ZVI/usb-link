//go:build windows && amd64 && usblink_local_remote

package launcher

import (
	"errors"
	"fmt"
	"os"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/app/macconnection"
)

func configureLocalRemote(m *connectioninstall.RemoteManager) {
	ipadncm.SetConnectionTimingPersistence(m.SaveLocalTimingPreference, m.ReadLocalTimingPreference)
	ipadncm.SetPhotoIsolationPersistence(m.SaveLocalPhotoPreference, m.ReadLocalPhotoPreference)
	ipadncm.SetLocalRemoteControl(func(enabled bool) (string, error) {
		if enabled {
			// Timing preference errors stay visible in their own snapshot;
			// they must not disable the independent USB installation channel.
			_ = ipadncm.RestoreConnectionTimingPreference()
		}
		if e := m.Enable(enabled); e != nil {
			return "", e
		}
		status, _ := m.Info()
		return status, nil
	}, m.SaveLocalDebugPreference, m.ReadLocalDebugPreference, m.SetLocalDebugIntent, m.LocalDebugTransportStatus, m.LocalRemoteInitializationCode())
	macconnection.LocalMaintenanceInvitation = func() string { _, invitation := m.Info(); return invitation }
}

func configureLocalRemoteUnavailable(err error) {
	code := connectioninstall.RemoteInitializationCode(err)
	diagnostic := connectioninstall.RemoteInitializationDiagnostics(err)
	ipadncm.SetLocalRemoteUnavailable(code)
	ipadncm.SetConnectionTimingPersistence(func(string) error { return errors.New(code) }, func() (string, error) { return "", errors.New(code) })
	ipadncm.SetPhotoIsolationPersistence(func(bool) error { return errors.New(code) }, func() (bool, error) { return false, errors.New(code) })
	macconnection.DeveloperStatus = func() any {
		return map[string]any{"enabled": false, "listening": false, "initialization_code": code, "initialization_failure": diagnostic}
	}
}

//go:noinline
func handleLocalRemoteCommand() bool {
	if len(os.Args) < 2 {
		return false
	}
	mode := os.Args[1]
	if mode != connectioninstall.LocalRemoteElevateArgument && mode != connectioninstall.LocalRemoteDispatchArgument && mode != connectioninstall.LocalRemoteInstallArgument {
		return false
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "LOCAL_REMOTE_ARGUMENT_INVALID")
		return true
	}
	var err error
	switch mode {
	case connectioninstall.LocalRemoteElevateArgument:
		err = connectioninstall.LaunchLocalRemoteElevation(os.Args[2])
	case connectioninstall.LocalRemoteDispatchArgument:
		err = connectioninstall.DispatchLocalRemoteInstall(os.Args[2])
	case connectioninstall.LocalRemoteInstallArgument:
		err = connectioninstall.RunLocalRemoteInstall(os.Args[2], version, installBundledRelease)
	}
	if err != nil {
		// Helpers execute from App. A blocking dialog would keep that image
		// locked during publication; UAC cancellation exits quietly as well.
		if mode != connectioninstall.LocalRemoteInstallArgument {
			fmt.Fprintln(os.Stderr, err)
			return true
		}
		var uiError *connectioninstall.LocalRemoteUILaunchError
		if errors.As(err, &uiError) {
			dialog("新版本已安裝完成，但尚未確認介面開啟。\n"+err.Error(), 0x30)
		} else {
			dialog("本地遠端安裝未完成。\n"+err.Error(), 0x10)
		}
	}
	return true
}
