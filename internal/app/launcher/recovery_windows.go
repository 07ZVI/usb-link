//go:build windows && amd64

package launcher

import (
	"context"
	"fmt"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/app/startuptelemetry"
	"suhang/usbnet/internal/app/usbhost"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"time"
)

// This snapshot contains recovery proofs and error codes, never pairing tokens,
// USB instance IDs, arbitrary files or executable commands.
func recoverySummary(r Result) map[string]any {
	macEntries := []map[string]string{}
	for _, entry := range r.MacRecovery.Entries {
		if len(macEntries) >= 8 {
			break
		}
		output := entry.Output
		if len(output) > 2048 {
			output = output[len(output)-2048:]
		}
		macEntries = append(macEntries, map[string]string{"error": entry.Error, "cleanup_output": output})
	}
	return map[string]any{"version": version, "started_utc": r.Started, "stage": r.Stage, "error": r.Error, "application_recovery": r.ApplicationRecovery, "grouping_recovery": r.Recovery, "mac_recovery": map[string]any{"error": r.MacRecovery.Error, "entries": macEntries}}
}
func approveRecoveryUpdate(next string) bool {
	yes, _ := ipadncm.NativePanel("管理員確認 USB 修復升級", "已收到並驗證 USB Link "+next+"。\r\n確認後會正常結束目前版本並安裝修復版。", "同意並安裝", nil)
	return yes
}
func runRecoveryMaintenance(r Result, recoveryDir, installed string, resident bool, stopStartup context.CancelFunc) {
	parent := context.Background()
	if owner := liveCore.Load(); owner != nil {
		parent = owner.ctx
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ipadncm.SetConnectionContext(ctx)
	ipadncm.SetDesktopLauncher(func() (string, error) {
		return prepareBundledDesktop()
	})
	var e error
	developerRemote, e = connectioninstall.NewRecoveryRemoteManager(version, installed, cancel, func() string { return "" }, approveRecoveryUpdate)
	if e != nil {
		dialog("USB 恢復維護無法啟動："+e.Error(), 0x10)
		return
	}
	defer developerRemote.Close()
	if coreProcessMode {
		developerRemote.SetUpdateNotifier(func(v, phase string) error { return coreUpdateNotices.Notify(ctx, v, phase) })
	} else {
		developerRemote.SetUpdateNotifier(ipadncm.NotifyRemoteUpdate)
	}
	developerRemote.SetIPadDiagnostic(func(kind string) (any, error) {
		switch kind {
		case "IPADNETWORKONLYSTATE":
			return ipadncm.SimplifiedIPadNetworkSnapshot(), nil
		default:
			return nil, fmt.Errorf("recovery permits read-only iPad status only")
		}
	}, func() bool { return ipadncm.NetworkOnlySnapshot().Busy })

	developerRemote.SetRuntimeStatus(func() (string, string) { return "USB_RECOVERY_MAINTENANCE", r.Error })
	summary := recoverySummary(r)
	developerRemote.SetRuntimeDetails(func() any {
		return map[string]any{"startup_recovery": summary, "ipad_network": ipadncm.SimplifiedIPadNetworkSnapshot(), "ipad_software_reconnect": ipadncm.IPadSoftwareReconnectSnapshot()}
	})
	var closeUI func()
	var problem string
	if coreProcessMode {
		closeUI, problem = ipadncm.StartHeadlessConnectionMonitor(ctx, cancel)
	} else {
		closeUI, problem = ipadncm.StartConnectionMonitor(ctx, cancel, resident)
	}
	if problem != "" {
		dialog(problem, 0x10)
		return
	}
	defer func() { cancel(); stopStartup(); closeUI() }()
	ipadncm.SetMonitorStatus("USB_RECOVERY_WAITING", r.Error)
	var attempted string
	wasEnabled := false
	for ctx.Err() == nil {
		enabled := developerRemote.Enabled()
		if enabled && !wasEnabled {
			attempted = ""
		}
		wasEnabled = enabled
		root := macconnection.CurrentRoot()
		if root == "" {
			attempted = ""
		}
		if ipadncm.ConsumeMacRecoveryRetry() {
			attempted = ""
		}
		if root != "" && attempted != root && developerRemote.Enabled() {
			attempted = root
			runUSBRecovery(ctx, root, r.Error, developerRemote, summary, recoveryDir)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
func runUSBRecovery(parent context.Context, root, problem string, m *connectioninstall.RemoteManager, summary any, recoveryDir string) {
	runUSBRecoveryMode(parent, root, problem, m, summary, recoveryDir, false)
}

func sharedHostStartupDiagnostics(dir string) any {
	return map[string]any{"observation_only": true, "supervisor": usbhost.SharedHostSupervisorDetails(), "startup_ownership": usbhost.InspectStartupOwnership(dir), "script_failures": netconfig.NetworkScriptFailureDiagnostics(), "startup_task": connectioninstall.LastStartupTaskObservation(), "startup_timing": startuptelemetry.Snapshot()}
}

// This worker owns no host lease and does not change unknown restoration
// intent. Raw transport uses the existing protected owner/authentication path.
// Return of a raw attempt is not permission to prompt again: only an explicit
// retry, a new USB root/presence or a developer off/on transition re-arms it.
func runHostWaitingUSBRecovery(ctx context.Context, _ string, m *connectioninstall.RemoteManager, summary any, dir string) {
	if m == nil {
		return
	}
	var attempted string
	wasEnabled := false
	for ctx.Err() == nil {
		enabled := m.Enabled()
		if enabled && !wasEnabled {
			attempted = ""
		}
		wasEnabled = enabled
		root := macconnection.CurrentRoot()
		if root == "" || ipadncm.ConsumeMacRecoveryRetry() {
			attempted = ""
		}
		if enabled && root != "" && root != attempted {
			attempted = root
			runUSBRecoveryMode(ctx, root, "WAITING_SHARED_HOST", m, summary, dir, true)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// Local recovery is performed before this fallback by RecoverIPadSoftwareReconnect,
// RecoverApplicationSession and macconnection.RecoverWithReport. This fallback
// previously served developer upgrades/diagnostics over raw USB; it never repaired
// local installation or rollback journals. Preserve the local error display.
func runUSBRecoveryMode(parent context.Context, root, problem string, m *connectioninstall.RemoteManager, summary any, recoveryDir string, waitingHost bool) {
	if parent.Err() == nil && !waitingHost {
		ipadncm.UpdateMacMonitor(macconnection.Result{Stage: "USB_RECOVERY_WAITING", Error: problem})
	}
}
