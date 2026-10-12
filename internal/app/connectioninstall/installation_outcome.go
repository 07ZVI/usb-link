package connectioninstall

import (
	"context"
	"fmt"
)

// A successful recovery is not a successful installation of the requested
// release. Keep that distinction at the caller boundary of the coordinator.
func installationOutcomeError(t InstallationTransaction) error {
	if t.Phase == InstallComplete {
		return nil
	}
	if t.Phase == InstallRolledBack {
		if t.Previous == nil {
			return fmt.Errorf("INSTALL_REQUESTED_VERSION_NOT_INSTALLED: 本次程序安装未完成，已撤回本次程序发布；请重新运行安装包。")
		}
		return fmt.Errorf("INSTALL_PREVIOUS_VERSION_RESTORED: 更新未完成，已恢复原有版本；本次新版本尚未安装。")
	}
	return fmt.Errorf("INSTALL_COMPLETION_PENDING: %s", t.Phase)
}

type cleanUninstallProbes struct {
	Source, Binding, Registration, Service func() (bool, error)
}

func cleanCompletedUninstall(phase InstallationPhase, probes cleanUninstallProbes) (bool, error) {
	if phase != InstallComplete {
		return false, nil
	}
	for _, probe := range []func() (bool, error){probes.Source, probes.Binding, probes.Registration, probes.Service} {
		if probe == nil {
			return false, fmt.Errorf("INSTALL_ABSENCE_PROBE_REQUIRED")
		}
		present, e := probe()
		if e != nil {
			return false, e
		}
		if present {
			return false, nil
		}
	}
	return true, nil
}

// Repeat installs need all four obligations, including metadata repair and a
// fresh authenticated initialization result, even when every file already fits.
type completedReinstallActions struct {
	Verify, Metadata, Start func() error
	Await                   func(context.Context) error
}

func confirmCompletedReinstall(ctx context.Context, phase InstallationPhase, a completedReinstallActions) error {
	if phase != InstallComplete {
		return fmt.Errorf("INSTALL_ACCEPTED_TRANSACTION_REQUIRED")
	}
	for _, action := range []func() error{a.Verify, a.Metadata, a.Start} {
		if e := ctx.Err(); e != nil {
			return e
		}
		if action == nil {
			return fmt.Errorf("INSTALL_REINSTALL_ACTION_REQUIRED")
		}
		if e := action(); e != nil {
			return e
		}
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if a.Await == nil {
		return fmt.Errorf("INSTALL_REINSTALL_ACTION_REQUIRED")
	}
	return a.Await(ctx)
}
