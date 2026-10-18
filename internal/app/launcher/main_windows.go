//go:build windows && amd64

package launcher

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/app/remoteupdate"
	"suhang/usbnet/internal/app/startupopt"
	"suhang/usbnet/internal/app/startuptelemetry"
	"suhang/usbnet/internal/app/uistartup"
	"suhang/usbnet/internal/app/usbhost"
	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/dependencies"
	"suhang/usbnet/internal/diagnostics/attemptlog"
	"suhang/usbnet/internal/diagnostics/memorydiag"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/sharing/fileshare"
	"suhang/usbnet/internal/transport/wintun"
	"sync/atomic"
	"time"
	"unsafe"
)

var version = buildinfo.Version

var applicationExitCleanupPending atomic.Bool

// Exit UI must not treat isolation restoration as proof that the independent
// network/session cleanup succeeded. Detailed evidence remains in the result.
func ApplicationExitCleanupError() error {
	if applicationExitCleanupPending.Load() {
		return fmt.Errorf("APPLICATION_EXIT_CLEANUP_PENDING")
	}
	return nil
}

// Publisher-only diagnostic candidate: ordinary iPad auto-connect is held.
// Default OFF; this is not a persisted user setting or remotely supplied flag.
const unpairedDiagnosticStartupHold = false

// Frozen publisher-only rollback fixture. Never selected by IPC, environment or UI.
const intentionalCandidateFailure = false

// Selected by the publisher in the frozen source; never read from an
// environment variable, device, web request, or interactive command line.
const startupSelection = "native_task,parallel_prepare,firewall_shadow,combined_legacy_network,dad_zero,wintun_module_hold"

var remoteInstallID string
var coreProcessMode bool
var bootstrapCreatedCore bool
var developerRemote *connectioninstall.RemoteManager
var serviceDiagnosticDirectory atomic.Value
var nativeFirewallSchema atomic.Value
var nativeInterfaceSchema atomic.Value
var nativeReadCompatibility atomic.Value

var authorization *ipadncm.ConnectionAuthorization
var attemptHistory attemptlog.History

var appleComponent, _ = dependencies.Lookup("apple-support")

func Main() {
	dependencies.Configure(connectioninstall.DependencyDirectory, connectioninstall.VerifyDependencyPath)
	dependencies.Default.SetOfflineArchiveSource(connectioninstall.LocalDependencyArchive)
	dependencies.Default.SetBundledArchiveSource(bundledDependencyArchive)
	if dispatchWintunLifecycleProbe() {
		return
	}
	var selected []string
	if startupSelection != "" {
		selected = strings.Split(startupSelection, ",")
	}
	if err := startupopt.Configure(selected); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	connectioninstall.SetNativeStartupEnabled(startupopt.Enabled(startupopt.NativeTask))
	netconfig.SetNativeNetworkEnabled(startupopt.Enabled(startupopt.NativeNetwork))
	netconfig.SetResidentFirewallEnabled(startupopt.Enabled(startupopt.ResidentFirewall))
	netconfig.SetCombinedLegacyNetworkEnabled(startupopt.Enabled(startupopt.CombinedLegacyNetwork))
	netconfig.SetFirewallShadowEnabled(startupopt.Enabled(startupopt.FirewallShadow))
	wintun.SetModuleLifetimeHoldEnabled(startupopt.Enabled(startupopt.WintunModuleHold))
	interfaceconfig.SetOwnedDADZeroEnabled(startupopt.Enabled(startupopt.DADZero))
	interfaceconfig.SetPersistentEnabled(startupopt.Enabled(startupopt.PersistentConfig))
	startuptelemetry.Init()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if len(os.Args) == 2 && os.Args[1] == "--core-service" {
		runCoreService()
		return
	}
	runApplication(ctx, cancel, false)
}

func runApplication(ctx context.Context, cancel context.CancelFunc, service bool) {
	applicationExitCleanupPending.Store(false)
	memorydiag.RecordStage("parent_main_enter")
	ipadncm.SetProductVersion(version)
	if handleLocalRemoteCommand() {
		return
	}

	if len(os.Args) == 2 && os.Args[1] == "--licenses" {
		dir, e := os.Getwd()
		if e == nil {
			e = writeNotices(dir)
		}
		if e != nil {
			dialog("無法匯出授權說明。", 0x10)
		} else {
			dialog("已匯出 LICENSES.txt 與來源說明。", 0x40)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == connectioninstall.PreparedInstallArgument && remoteInstallID == "" {
		dialog("請直接執行安裝程式；舊版續接選項已停用。", 0x10)
		return
	}
	preparedInstall := len(os.Args) == 2 && os.Args[1] == connectioninstall.PreparedInstallArgument
	resident := service || len(os.Args) == 2 && os.Args[1] == "--resident"
	uninstall := len(os.Args) == 2 && os.Args[1] == "--uninstall"
	if len(os.Args) > 1 && !resident && !uninstall && !preparedInstall && remoteInstallID == "" {
		dialog("無法識別啟動選項。", 0x10)
		return
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		exe, e := os.Executable()
		if e != nil {
			return
		}
		verb, _ := windows.UTF16PtrFromString("runas")
		path, _ := windows.UTF16PtrFromString(exe)
		var params *uint16
		if resident || uninstall || preparedInstall {
			params, _ = windows.UTF16PtrFromString(os.Args[1])
		}
		v, _, _ := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW").Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(params)), 0, 1)
		if v <= 32 {
			dialog("未取得管理員權限，沒有安裝或檢查。", 0x10)
		}
		return
	}
	// Setup is a native wizard before any dependency download or installation.
	// An owned installed image keeps its ordinary application/service path.
	if !service && !resident && !uninstall && !preparedInstall && remoteInstallID == "" {
		if exe, e := os.Executable(); e != nil || connectioninstall.Verify(exe) != nil {
			runSetupWizard(ctx)
			return
		}
	}
	if !service && !uninstall {
		if remoteInstallID == "" {
			if err := connectioninstall.PreflightLocalInstallationForSetup(version); err != nil {
				dialog("安裝前檢查未通過。\n"+err.Error(), 0x10)
				return
			}
		}
		err := dependencies.EnsureWithProgressIfMissing(ctx, "dotnet")
		if err != nil {
			dialog("桌面元件尚未齊備，核心仍可使用備用介面。\n請聯網後重試。\n"+err.Error(), 0x30)
		}
	}
	if preparedInstall {
		if err := connectioninstall.ValidatePreparedInstall(version); err != nil {
			dialog("安裝續接驗證未通過；已保留目前版本。"+err.Error(), 0x10)
			return
		}
	}
	if resident || uninstall {
		exe, e := os.Executable()
		if e != nil || connectioninstall.Verify(exe) != nil {
			dialog("啟動來源驗證未通過。請重新執行安裝程式。", 0x10)
			return
		}
	}
	if !service && !preparedInstall && remoteInstallID == "" {
		if exe, err := os.Executable(); err == nil && connectioninstall.Verify(exe) == nil {
			if binding, err := connectioninstall.CurrentCoreBinding(); err == nil {
				if !strings.EqualFold(binding.Executable, exe) {
					if connectioninstall.Verify(binding.Executable) != nil {
						return
					}
					args := []string{}
					if resident {
						args = append(args, "--resident")
					}
					if uninstall {
						args = []string{"--uninstall"}
					}
					child := exec.Command(binding.Executable, args...)
					if child.Start() == nil {
						_ = child.Process.Release()
					}
					return
				}
				if !uninstall {
					runCoreLoginUI(ctx, cancel, exe, resident)
					return
				}
			}
		}
	}
	if !service && !resident && !uninstall && !preparedInstall && remoteInstallID == "" {
		runSetupWizard(ctx)
		return
	}

	// Cancellation precedes even stopping the running owner or opening recovery.
	// Merely selecting uninstall must not withdraw persistent protection.
	if uninstall {
		yes, _ := ipadncm.NativePanel("卸載USB Link", "將恢復本程式改動的 iPad 照片介面、USB 分組與 Apple 服務原設定，取消本帳戶的開機啟動、刪除本程式和已記住的設備，關閉本程式建立的 SMB 共享及專用帳戶，恢復本程式改動的 Guest 設定。\r\n\r\n會保留共享資料夾內的檔案、其他 Windows 共享、蘋果官方元件、共用驅動及診斷資料。正在使用的程式檔案會安排在下一次重啟 Windows 後刪除。", "卸載", nil)
		if !yes {
			return
		}
		exe, e := os.Executable()
		if e != nil {
			return
		}
		if e = connectioninstall.CloseInstalledLoginClients(ctx, exe); e != nil {
			dialog("卸載尚未開始，無法正常關閉舊介面。\n"+e.Error(), 0x10)
			return
		}
		if err := prepareCoreUninstall(ctx); err != nil {
			dialog("卸載未完成：無法先通知核心恢復持久網卡原設定。已保留程式與原值記錄。"+err.Error(), 0x10)
			return
		}
	}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		dialog("無法找到系統工具。", 0x10)
		return
	}
	r := Result{Protocol: "SUHANG-USB-EASY/2", Version: version, Started: time.Now().UTC().Format(time.RFC3339), Stage: "RECOVERY_CHECK", ComponentVersion: appleComponent.Version, ComponentHash: appleComponent.Digest}
	var handoff *connectioninstall.UpgradeStop
	if !resident {
		handoff = connectioninstall.RequestPreviousStop()
		defer handoff.Close()
		r.UpgradeStop = handoff
	}
	var recoveryDir, recoveryError string
	var lock windows.Handle
	if handoff != nil {
		recoveryDir, lock, recoveryError = handoff.WaitForCleanup(ipadncm.OpenGroupingRecoveryStore)
	} else {
		recoveryDir, lock, recoveryError = ipadncm.OpenGroupingRecoveryStore()
	}
	if recoveryError != "" {
		installationFailure(&r, recoveryError, "安裝程式尚未取得連線管理權。已嘗試正常結束可驗證的舊版，具體結果已保存於診斷。")
		return
	}
	dependencies.Default.SetLocalSource(func(a dependencies.Asset) string {
		if a.ID == "wintun" {
			return macconnection.PinnedLegacyWintun(recoveryDir)
		}
		return ""
	})
	if service {
		serviceDiagnosticDirectory.Store(recoveryDir)
	}
	defer func() {
		if lock != 0 {
			windows.CloseHandle(lock)
		}
	}()
	if remoteInstallID != "" {
		_ = macconnection.RecordUpgradeEvidence(recoveryDir, version, "RECOVERY_LOCK_ACQUIRED", "")
	}
	var installed string
	if service {
		installed, e = os.Executable()
		if e != nil || connectioninstall.VerifyCoreExecutable(installed) != nil {
			return
		}
		settingsDir, settingsError := connectioninstall.StateDirectory()
		if settingsError != nil {
			return
		}
		if e = ipadncm.InitConnectionSettings(settingsDir, func(enabled bool) error { return setCoreStartup(ctx, enabled, installed) }); e != nil {
			return
		}
	} else if !uninstall {
		installed, e = connectioninstall.Prepare(version)
		if e != nil {
			installationFailure(&r, "PROGRAM_FILES_PREPARE_FAILED", "無法安全安裝本程式，現有版本已保留。\n請先關閉正在執行的舊版，再執行本版本。")
			return
		}
		// The downloaded setup is only a bootstrapper. Core service rules must use
		// the verified executable in Program Files, never grant the Downloads path.
		launched, e := connectioninstall.LaunchPrepared(installed, func() error {
			if err := windows.CloseHandle(lock); err != nil {
				return err
			}
			lock = 0
			return nil
		})
		if e != nil {
			installationFailure(&r, "INSTALLED_PROGRAM_LAUNCH_FAILED", "程式已安裝，但無法啟動已驗證的安裝版本。\n"+e.Error())
			return
		}
		if launched {
			return
		}
		if e = connectioninstall.MigrateBrand(); e != nil {
			installationFailure(&r, "BRAND_MIGRATION_FAILED", "USB Link 資料遷移未完成；原有檔案已保留。\n"+e.Error())
			return
		}
		settingsDir := filepath.Dir(filepath.Dir(installed))
		if e = ipadncm.InitConnectionSettings(settingsDir, func(enabled bool) error { return connectioninstall.SetStartupContext(ctx, enabled, installed) }); e != nil {
			installationFailure(&r, "PROTECTED_PREFERENCES_LOAD_FAILED", "無法讀取受保護的設定，沒有開始連線。")
			return
		}
		if e = connectioninstall.Register(installed, version); e != nil {
			installationFailure(&r, "OWNED_INSTALL_REGISTRATION_FAILED", "程式已保存，但安裝登錄未完成；現有登錄已保留。\n"+e.Error())
			return
		}
		if e = connectioninstall.UpdateShortcut(installed, false); e != nil {
			installationFailure(&r, "OWNED_SHORTCUT_UPDATE_FAILED", "程式已安裝，但開始功能表捷徑未完成；已保留現有捷徑。")
			return
		}
		// The installer owns no USB work after this point. SCM must acquire the
		// same protected recovery lock before entering the one core loop.
		if e = windows.CloseHandle(lock); e != nil {
			return
		}
		lock = 0
		var created bool
		if preparedInstall {
			created, e = connectioninstall.InstallPreparedCoreServiceObserved(installed, version)
		} else {
			created, e = connectioninstall.InstallCoreServiceObserved(installed)
		}
		bootstrapCreatedCore = created && remoteInstallID != ""
		if e != nil {
			if bootstrapCreatedCore {
				if binding, err := connectioninstall.CurrentCoreBinding(); err == nil && binding.Executable == installed {
					_ = connectioninstall.RemoveExpectedCoreService(binding)
				}
			}
			installationFailure(&r, "CORE_SERVICE_INSTALL_FAILED", e.Error())
			return
		}
		runCoreLoginUI(ctx, cancel, installed, resident)
		return
	}
	memorydiag.RecordStage("parent_installation_ready")
	if service && !uninstall {
		// Observe the existing strict reboot fence before slow legacy cleanup.
		// Failure only records diagnostics; the supervisor retains authority.
		early := recoverInterruptedHostEarly(ctx, recoveryDir)
		r.HostEarlyRecovery = &early
	}
	retired, legacyWarning, legacyError := macconnection.RetireLegacyForUpgrade()
	r.LegacyServiceRetired, r.LegacyCleanupWarning = retired, legacyWarning
	if legacyError != nil {
		r.LegacyMigrationError = legacyError.Error()
		installationFailure(&r, "LEGACY_SERVICE_UPGRADE_FAILED", "舊版服務的自動停止或清理未完成。詳細原因已保存於診斷，沒有開始新的連線。")
		return
	}
	if !uninstall {
		if e := ipadncm.RecoverIPadSoftwareReconnect(recoveryDir); e != nil {
			r.Stage, r.Error = "SOFTWARE_RECONNECT_RESTORE_PENDING", e.Error()
			_, _ = save(r)
			runRecoveryMaintenance(r, recoveryDir, installed, resident, cancel)
			return
		}
		if e := ipadncm.InitIPadSoftwareReconnect(recoveryDir, false); e != nil {
			installationFailure(&r, "SOFTWARE_RECONNECT_INITIALIZATION_FAILED", e.Error())
			return
		}
		r.ApplicationRecovery = ipadncm.RecoverApplicationSession(recoveryDir, system)
		// One compatibility migration restores AMDS/WPD originals only. Its failure
		// keeps iPad paused while the independent Mac and signed-upgrade path run.
		_ = ipadncm.InitSimplifiedIPadNetwork(recoveryDir)
		r.Recovery = ipadncm.InspectPersistentNetworkGrouping(recoveryDir)
		ipadncm.RecordSimplifiedGroupingWarning(r.Recovery.Error)
		defer ipadncm.StartConnectionArchive(ctx, recoveryDir)()
		defer shutdowntrace.Wrap(shutdowntrace.PhaseEnvironmentStop, ipadncm.StartConnectionEnvironment(ctx, version))()
		defer shutdowntrace.Wrap(shutdowntrace.PhaseDefaultIsolationStop, ipadncm.StartDefaultNetworkIsolation(ctx, recoveryDir))()
		defer shutdowntrace.Wrap(shutdowntrace.PhaseWPDStop, ipadncm.StartLocalWPDTrace(ctx, recoveryDir))()
		defer shutdowntrace.Wrap(shutdowntrace.PhaseUSBStop, ipadncm.StartLocalUSBTrace(ctx, recoveryDir))()
		defer shutdowntrace.Wrap(shutdowntrace.PhasePnPStop, ipadncm.StartLocalPnPTrace(ctx))()
		defer shutdowntrace.Wrap(shutdowntrace.PhaseDirectStop, ipadncm.StartLocalNCMDirect(ctx, recoveryDir))()
	}
	var macRecovery macconnection.RecoveryReport
	var macRecoveryError error
	if !uninstall {
		macRecovery, macRecoveryError = macconnection.RecoverWithReport(recoveryDir)
	}
	r.MacRecovery = macRecovery
	if macRecoveryError != nil {
		r.Stage, r.Error = "MAC_RECOVERY_UNCONFIRMED", macRecoveryError.Error()
		if !uninstall {
			_, _ = save(r)
			runRecoveryMaintenance(r, recoveryDir, installed, resident, cancel)
		} else {
			installationFailure(&r, "MAC_RECOVERY_UNCONFIRMED", macconnection.RecoveryMessage(macRecoveryError.Error()))
		}
		return
	}
	if r.ApplicationRecovery.Error != "" || r.ApplicationRecovery.Pending && !r.ApplicationRecovery.JournalCleared {
		r.Stage, r.Error = "APPLICATION_RECOVERY_PENDING", r.ApplicationRecovery.Error
		_, _ = save(r)
		if !uninstall {
			runRecoveryMaintenance(r, recoveryDir, installed, resident, cancel)
		}
		return
	}
	if uninstall {
		var cleanupError error
		var reboot bool
		r.MacRecovery, reboot, cleanupError = recoverUninstallInterfaces(ctx, recoveryDir, system, lock)
		if cleanupError != nil {
			dialog("卸載未完成：核心、USB 或網卡原值尚未核對恢復；已保留程式及回執。"+cleanupError.Error(), 0x10)
			return
		}
		if reboot {
			dialog("開機啟動已取消。程式檔案將在下一次重啟 Windows 後移除；不會強制重啟。", 0x40)
		} else {
			dialog("已卸載USB Link。", 0x40)
		}
		return
	}
	if service {
		if e := connectioninstall.AcceptInstallationReady(); e != nil {
			r.Stage, r.Error = "INSTALL_ACCEPTANCE_FAILED", e.Error()
			_, _ = save(r)
			return
		}
	}
	var pruned []string
	defer ipadncm.StartStartupTimingEvidence(ctx, recoveryDir, version)()

	// Optional task reconciliation shares the settings mutation lock but never
	// blocks network preparation. Join before releasing the protected owner, so
	// an old process cannot replace a newer version's task after its handoff.
	startupDone := make(chan struct{})
	go func() {
		defer close(startupDone)
		ipadncm.ReconcileStartupSettings(func(enabled bool) error { return setCoreStartup(ctx, enabled, installed) })
	}()
	defer func() { cancel(); <-startupDone }()
	if desktopName, err := bundledDesktopDirectoryName(); err == nil {
		defer connectioninstall.StartInstallationCleanup(ctx, version, desktopName, func() ([]string, []string) {
			return macconnection.PruneRetiredRuntimes(recoveryDir)
		})()
	}
	fileshare.USB.Native.Store(true)
	ipadncm.SetConnectionContext(ctx)
	ipadncm.SetDesktopLauncher(func() (string, error) {
		defer debug.FreeOSMemory()
		return prepareBundledDesktop()
	})
	var lastRecovery atomic.Value
	lastRecovery.Store(recoverySummary(r))
	developerRemote, e = connectioninstall.NewRemoteManager(version, installed, cancel, func() string {
		if !ipadncm.MaintenanceReady() {
			return ""
		}
		return macconnection.MaintenanceGUID(recoveryDir)
	}, func(next string) bool {
		if !windows.GetCurrentProcessToken().IsElevated() {
			return false
		}
		yes, _ := ipadncm.NativePanel("管理員確認 USB 升級", "已收到並驗證USB Link "+next+"。\r\n\r\n確認後會中斷目前 USB 串流／傳輸、正常結束舊版並安裝新版。啟動失敗時嘗試恢復上一版。\r\n\r\n此視窗由目前具管理員權限的程式顯示；開啟開發者調試不代表同意本次安裝。", "同意並安裝", nil)
		return yes
	})
	if e != nil {
		fmt.Fprintln(os.Stderr, "LOCAL_UPDATE_JOURNAL_UNAVAILABLE:", e)
		configureLocalRemoteUnavailable(e)
		_ = macconnection.RecordUpgradeEvidence(recoveryDir, version, "LOCAL_REMOTE_INITIALIZATION_FAILED", connectioninstall.RemoteInitializationCode(e))
	} else {
		defer developerRemote.Close()
		if service {
			developerRemote.SetUpdateNotifier(func(v, phase string) error { return coreUpdateNotices.Notify(ctx, v, phase) })
		} else {
			developerRemote.SetUpdateNotifier(ipadncm.NotifyRemoteUpdate)
		}
		developerRemote.SetResourceObserver(resourceObserver)
		developerRemote.SetMeasurementUIControl(ipadncm.MeasurementUI)
		developerRemote.SetMeasurementUIBaseline(ipadncm.MeasurementUIBaseline)
		developerRemote.SetMeasurementGuardBaseline(ipadncm.MeasurementGuardBaseline)
		developerRemote.SetMeasurementRootBaseline(macconnection.SetRootPollingBaseline)
		developerRemote.SetIPadDiagnostic(func(kind string) (any, error) {
			switch kind {
			case "IPADUNPAIREDPREFLIGHT":
				var metadata ipadncm.UnpairedPairMetadataReadback
				preflight := ipadncm.InspectUnpairedExperimentPreflight(func(s ipadncm.Snapshot) (ipadncm.UnpairedPairMetadata, error) {
					metadata = ipadncm.InspectUnpairedPairMetadataReadback(s)
					if metadata.Error != "" {
						return metadata.Metadata, fmt.Errorf("%s", metadata.Error)
					}
					return metadata.Metadata, nil
				})
				return map[string]any{"preflight": preflight, "pair_file_metadata": metadata}, nil
			case "IPADUNPAIREDPREP", "IPADUNPAIREDFINISH", "IPADUNPAIREDREPLIED", "IPADAMDSRUNNING", "IPADAMDSSTOPPED":
				return nil, fmt.Errorf("legacy isolation diagnostics retired")
			case "IPADUNPAIREDSTATE":
				return ipadncm.UnpairedExperimentSnapshot(), nil
			case "IPADSOFTRECONNECT":
				if err := ipadncm.RequestIPadSoftwareReconnect(ctx); err != nil {
					return nil, err
				}
				return ipadncm.IPadSoftwareReconnectSnapshot(), nil
			case "IPADSOFTRECONNECTON", "IPADSOFTRECONNECTOFF":
				if err := ipadncm.RequestIPadSoftwareReconnectSetting(ctx, kind == "IPADSOFTRECONNECTON"); err != nil {
					return nil, err
				}
				return ipadncm.IPadSoftwareReconnectSnapshot(), nil
			case "IPADSOFTRECONNECTCANCEL":
				ipadncm.CancelIPadSoftwareReconnect()
				return ipadncm.IPadSoftwareReconnectSnapshot(), nil
			case "IPADSOFTRECONNECTSTATE":
				return ipadncm.IPadSoftwareReconnectSnapshot(), nil
			case "IPADSTARTUPSTATE":
				return ipadncm.StartupReadinessDiagnostics(), nil
			case "USBHOSTSTARTUPSTATE":
				return sharedHostStartupDiagnostics(recoveryDir), nil
			case "USBSTARTUPON":
				if !ipadncm.RemoteUSBConnectionHealthy() {
					return nil, fmt.Errorf("healthy Mac USB connection required")
				}
				e := ipadncm.RequestStartupEnabled()
				if e == nil {
					observed, readError := connectioninstall.ReadStartupTaskState(installed)
					e = readError
					if e == nil && (!observed.Enabled || observed.TaskCount != 1 || !ipadncm.ConnectionStartupEnabled()) {
						e = fmt.Errorf("STARTUP_REMOTE_READBACK_CHANGED")
					}
				}
				problem := ""
				if e != nil {
					problem = e.Error()
				}
				return map[string]any{"startup_enabled": ipadncm.ConnectionStartupEnabled(), "startup_task": connectioninstall.LastStartupTaskObservation(), "error": problem}, nil
			case "IPADWINTUNMODULEOFF", "IPADWINTUNMODULEON":
				if !ipadncm.RemoteUSBConnectionHealthy() {
					return nil, fmt.Errorf("healthy Mac USB connection required")
				}
				probe, cancelProbe := context.WithTimeout(ctx, 3*time.Minute)
				defer cancelProbe()
				result, err := runWintunLifecycleProbe(probe, kind == "IPADWINTUNMODULEON")
				problem := ""
				if err != nil {
					problem = err.Error()
				}
				return map[string]any{"result": result, "error": problem}, nil
			case "IPADTRUSTRECYCLESELFTEST":
				result, err := ipadncm.RunTrustRecycleNativeSelfTest()
				problem := ""
				if err != nil {
					problem = err.Error()
				}
				return map[string]any{"result": result, "error": problem}, nil
			case "IPADSIMPLIFIEDNATIVE":
				return map[string]any{"simplified": ipadncm.SimplifiedIPadNetworkSnapshot(), "native_readonly": ipadncm.NetworkOnlyLiveDiagnostics()}, nil
			case "IPADNETWORKONLYSTATE":
				return ipadncm.SimplifiedIPadNetworkSnapshot(), nil
			case "IPADNETWORKONLYON", "IPADNETWORKONLYOFF", "IPADNETWORKONLYPHASEON", "IPADNETWORKONLYPHASEOFF", "IPADDIAGNOSTICHOLD", "IPADDIAGNOSTICCANCEL", "IPADDIAGNOSTICRESULT", "IPADCANDIDATE3", "IPADCANDIDATE41", "IPADCANDIDATE42", "IPADCANDIDATE43", "IPADCANDIDATE5", "IPADCANDIDATEDEFAULT":
				return nil, fmt.Errorf("legacy isolation diagnostics retired")
			case "IPADCANDIDATESTATE":
				return ipadncm.IPadCandidateSnapshot(), nil
			default:
				return nil, fmt.Errorf("unknown iPad diagnostic")
			}
		}, func() bool {
			return ipadncm.UnpairedExperimentBusy() || ipadncm.AMDSModeDiagnosticActive() || ipadncm.IPadCandidateBusy() || ipadncm.NetworkOnlySnapshot().Busy || ipadncm.IPadSoftwareReconnectBusy()
		})
		developerRemote.SetRecoveryTest(func() error {
			if !ipadncm.RemoteUSBConnectionHealthy() {
				return fmt.Errorf("healthy Mac USB connection required")
			}
			return ipadncm.RequestMacRecoveryTest()
		})
		developerRemote.SetRuntimeStatus(ipadncm.ConnectionRuntimeStatus)
		developerRemote.SetStartupFailureDetails(func() remoteupdate.CandidateStartupObservation {
			s, ok := usbhost.SharedHostSupervisorDetails().(usbhost.SupervisorSnapshot)
			if !ok {
				return remoteupdate.CandidateStartupObservation{}
			}
			if s.FirstFailureCode != "" {
				return remoteupdate.CandidateStartupObservation{Phase: s.FirstFailurePhase, Code: s.FirstFailureCode, NativeError: s.FirstNativeError, NativeOperation: s.FirstNativeOperation, NativeHRESULT: s.FirstNativeHRESULT}
			}
			if s.FailureCode == "" {
				if mac, valid := macconnection.NativeStartupFailure(); valid {
					return remoteupdate.CandidateStartupObservation{Phase: "preparation", Code: "USB_HOST_NATIVE_STEP_FAILED", NativeOperation: mac.Operation, NativeHRESULT: mac.HRESULT}
				}
			}
			return remoteupdate.CandidateStartupObservation{Phase: s.FailurePhase, Code: s.FailureCode, NativeError: s.NativeError, NativeOperation: s.NativeOperation, NativeHRESULT: s.NativeHRESULT}
		})
		developerRemote.SetRichStartupFailureDetails(func() *remoteupdate.CandidateRichObservation {
			observed := macconnection.FailedStartupDiagnosticSnapshot()
			if observed == nil {
				return nil
			}
			result := &remoteupdate.CandidateRichObservation{
				BridgePID: observed.BridgePID, BridgeCreation: observed.BridgeCreation,
				BridgeSHA256: observed.BridgeSHA256, Failure: observed.Failure,
				NullProjection: observed.NullProjection, AnchorProjection: observed.AnchorProjection,
				DiagnosticTiming: observed.DiagnosticTiming,
			}
			if macconnection.MacCleanupFailureObservationValid(observed.CleanupFailure) {
				result.CleanupFailure = &remoteupdate.CandidateCleanupFailure{
					Phase: observed.CleanupFailure.Phase, Code: observed.CleanupFailure.Code,
					CleanupConfirmed: observed.CleanupFailure.CleanupConfirmed,
				}
			}
			return result
		})
		developerRemote.SetRuntimeDetails(func() any {
			return map[string]any{"intentional_candidate_failure": intentionalCandidateFailure, "wintun_module_lifetime": wintun.ModuleLifetimeSnapshot(), "firewall_shadow": netconfig.FirewallShadowDiagnostics(), "resident_firewall_failures": netconfig.ResidentFirewallFailureDiagnostics(), "ipad_address_projection": netconfig.IPadAddressProjectionSnapshot(), "owned_dad_observations": ownedDADDiagnostics(recoveryDir), "connections": ipadncm.ConnectionRuntimeDetails(), "mac_native_failure": macconnection.NativeStartupFailureDetails(), "recovery": lastRecovery.Load(), "startup_timing": startuptelemetry.Snapshot(), "startup_task": connectioninstall.LastStartupTaskObservation(), "startup_trigger_details": connectioninstall.NativeStartupTriggerDetails(), "core_service": connectioninstall.CoreServiceStatus(), "startup_options": startupopt.Snapshot(), "connection_measurement": ipadncm.ConnectionMonitorDiagnostics(), "native_firewall_schema": nativeFirewallSchema.Load(), "native_interface_schema": nativeInterfaceSchema.Load(), "native_read_compatibility": nativeReadCompatibility.Load(), "network_operation_timings": netconfig.NativeOperationTimingsSnapshot(), "interface_operation_timings": interfaceconfig.ObservationsSnapshot(), "shared_host_startup": sharedHostStartupDiagnostics(recoveryDir), "ui_events": ipadncm.UIEvents(), "ui_open_timings": uistartup.Snapshot(), "device_guard_watch": ipadncm.DeviceWatchDetails(), "ipad_network": ipadncm.SimplifiedIPadNetworkSnapshot(), "ipad_candidate": ipadncm.IPadCandidateSnapshot(), "ipad_unpaired_experiment": ipadncm.UnpairedExperimentSnapshot(), "ipad_software_reconnect": ipadncm.IPadSoftwareReconnectSnapshot()}
		})
		configureLocalRemote(developerRemote)
		macconnection.DeveloperStatus = func() any { return developerRemote.ListenerStatus() }
	}
	if buildinfo.LocalDiagnostics == "true" {
		macconnection.ConnectionArchiveEvidence = func() any {
			return map[string]any{"core_version": version, "connection_archive": ipadncm.ConnectionArchiveDiagnostics()}
		}
		ipadncm.StartRuntimeNetworkDiagnostics(ctx)
		ipadncm.StartTrustDiagnostics(ctx)
		macconnection.TrustEvidence = func() any {
			return map[string]any{"core_version": version, "ipad_trust_timeline": ipadncm.TrustDiagnosticsSnapshot(), "apple_service_trial": ipadncm.LocalTrustServiceTrialSnapshot()}
		}
		macconnection.TimingEvidence = func() any {
			return map[string]any{"core_version": version, "connection_timing": ipadncm.ConnectionTimingDiagnostics()}
		}
		macconnection.PhotoEvidence = func() any {
			return map[string]any{"core_version": version, "photo_isolation": ipadncm.PhotoIsolationDiagnostics()}
		}
		macconnection.WPDTraceEvidence = func() any {
			return map[string]any{"core_version": version, "wpd_trace": ipadncm.LocalWPDTraceDiagnostics()}
		}
		macconnection.NativeUSBEvidence = func() any {
			return map[string]any{"core_version": version, "local_usb_trace": ipadncm.LocalUSBTraceDiagnostics()}
		}
		macconnection.NativePnPEvidence = func() any {
			return map[string]any{"core_version": version, "pnp_native_trace": ipadncm.LocalPnPTraceDiagnostics()}
		}
		macconnection.PhotoPolicyEvidence = func() any {
			return map[string]any{"core_version": version, "photo_policy": ipadncm.LocalPhotoPolicyDiagnostics()}
		}
		macconnection.NCMDirectEvidence = func() any {
			return map[string]any{"core_version": version, "ncm_direct": ipadncm.LocalNCMDirectDiagnostics()}
		}
		macconnection.AMDSHoldEvidence = func() any {
			return map[string]any{"core_version": version, "amds_hold": ipadncm.LocalAMDSHoldDiagnostics(), "default_network_isolation": ipadncm.DefaultNetworkIsolationDiagnostics()}
		}
		macconnection.RuntimeNetworkEvidence = func() any {
			return map[string]any{"core_version": version, "ipad_runtime_network": ipadncm.RuntimeNetworkDiagnostics()}
		}
	}
	macconnection.ConnectionEvidence = func() any {
		return map[string]any{"core_version": version, "local_diagnostics_enabled": buildinfo.LocalDiagnostics == "true", "ipad_connection": ipadncm.CompactConnectionEvidence(), "desktop_snapshot": ipadncm.DesktopSnapshotDiagnostics(), "developer_debug": ipadncm.DeveloperDebugDiagnostics()}
	}
	if remoteInstallID != "" {
		_ = macconnection.RecordUpgradeEvidence(recoveryDir, version, "START_CONNECTION_MONITOR", "")
	}
	memorydiag.RecordStage("parent_remote_manager_ready")
	ipadncm.SetSharedHostWaitingDiagnostics(func() any { return sharedHostStartupDiagnostics(recoveryDir) })
	var closeUI func()
	var uiError string
	if service {
		closeUI, uiError = ipadncm.StartHeadlessConnectionMonitor(ctx, cancel)
	} else {
		closeUI, uiError = ipadncm.StartConnectionMonitor(ctx, cancel, resident)
	}
	if uiError != "" {
		dialog("無法開啟連線視窗："+uiError, 0x10)
		return
	}
	defer func() { cancel(); closeUI() }()
	memorydiag.RecordStage("parent_ui_monitor_started")
	ipadncm.ConfigureUnpairedDiagnosticStartupHold(unpairedDiagnosticStartupHold)
	macPayload, pe := macArchive("assets/mac-payload.zip")
	macManifest, me := payload.ReadFile("assets/mac-sources.json")
	if pe != nil || me != nil {
		dialog("Mac 傳輸元件缺失。", 0x10)
		return
	}
	stopHostSupervisor := usbhost.StartSharedHostSupervisor(ctx, func(attempt context.Context) (usbhost.PreparedHost, error) {
		return prepareSupervisedHost(attempt, recoveryDir, macPayload, macManifest)
	})
	defer stopHostSupervisor()
	stopInternet := startInternet(ctx)
	defer stopInternet()
	stopHostTriggers := ipadncm.WatchSharedHostDeviceChanges(ctx)
	defer stopHostTriggers()
	memorydiag.RecordStage("parent_host_supervisor_started")
	// Read only once, after the connection owner has started; frequent status
	// reads return this fixed schema observation rather than requerying WMI.
	schemaDone := make(chan struct{})
	go func() {
		defer close(schemaDone)
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		// This existing one-shot background diagnostic never publishes Ready,
		// chooses configuration, or runs on the UI opening path. Synchronous
		// provider calls cooperate between steps; this is not a hard COM timeout.
		if proof, ready := usbhost.Proof(); !netconfig.FirewallShadowEnabled() && ready && ipadncm.RemoteUSBConnectionHealthy() {
			if self, err := os.Executable(); err == nil {
				read, cancelRead := context.WithTimeout(ctx, 10*time.Second)
				nativeReadCompatibility.Store(netconfig.NativeReadCompatibility(read, proof, self))
				cancelRead()
			}
		} else {
			nativeReadCompatibility.Store(netconfig.NativeReadCompatibilityReport{Schema: 1, ReadOnly: true, WriteSupport: "unproven", Status: "healthy_host_unavailable"})
		}
		probe, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		if !netconfig.FirewallShadowEnabled() {
			nativeFirewallSchema.Store(netconfig.NativeFirewallSchemaSnapshot(probe))
		}
		nativeInterfaceSchema.Store(netconfig.NativeInterfaceConfigurationSchemaSnapshot(probe))
	}()
	defer func() { end := shutdowntrace.Begin(shutdowntrace.PhaseSchemaJoin); defer end(); cancel(); <-schemaDone }()
	recoveryBootSummary := recoverySummary(r)
	macDone := make(chan struct{})
	go func() {
		defer close(macDone)
		ipadncm.RunConcurrentMacArchive(ctx, recoveryDir, macPayload, macManifest, cancel, func(m macconnection.Result) {
			if m.BridgeStarted && !m.CleanupConfirmed {
				applicationExitCleanupPending.Store(true)
			}
			if developerRemote != nil && netconfig.NativeStepDiagnosticValid(m.NativeStartupFailure) {
				developerRemote.CaptureStartupFailureDetails()
			}
			if m.Error != "" || m.PreparationError != "" {
				_ = macconnection.RecordUpgradeEvidence(recoveryDir, version, m.Stage, m.Error+": "+m.PreparationError)
			}
		}, func(attempt context.Context, root, problem string) bool {
			if problem == "WAITING_SHARED_HOST" {
				runHostWaitingUSBRecovery(attempt, root, developerRemote, recoveryBootSummary, recoveryDir)
				return developerRemote != nil && developerRemote.Enabled()
			}
			if developerRemote == nil || !developerRemote.Enabled() {
				return false
			}
			runUSBRecovery(attempt, root, problem, developerRemote, recoveryBootSummary, recoveryDir)
			return developerRemote.Enabled()
		})
	}()
	defer func() { cancel(); <-macDone }()
	if remoteInstallID != "" {
		if developerRemote == nil {
			return
		}
		// A live UI is not a usable USB connection. A failed candidate must not
		// acknowledge readiness merely because its monitoring loop stays alive.
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			health := remoteupdate.Readiness{}
			fixtureStarted := time.Now()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					healthy := ipadncm.RemoteUSBConnectionHealthy()
					if intentionalCandidateFailure && (healthy || time.Since(fixtureStarted) >= 40*time.Second) {
						// The fixed publisher fixture also exits before the worker health
						// deadline if setup never becomes healthy. No Ready is synthesized.
						// Stop before the first genuine Ready observation; all ordinary
						// child joins, adapter cleanup and SCM exit still run.
						if connectioninstall.ValidateRemoteLaunch(remoteInstallID, version) == nil {
							_ = macconnection.RecordUpgradeEvidence(recoveryDir, version, "STAR8_INTENTIONAL_FAILURE", "STOP_BEFORE_READY")
						}
						cancel()
						return
					}
					if health.Observe(time.Now(), healthy) {
						if connectioninstall.RemoteReady(remoteInstallID, version) != nil {
							cancel()
						}
						return
					}
				}
			}
		}()
	}
	var cleanupPending bool
	for ctx.Err() == nil {
		memorydiag.RecordStage("parent_first_monitor_wait")
		if ipadncm.IPadUpgradeReservationHeld() {
			ipadncm.SetMonitorStatus("MONITOR_MAINTENANCE_PAUSED", "升級期間暫停新的 iPad 接入；Mac 管理連線保留")
			if !ipadncm.WaitForIPadSettingsRecovery(ctx) {
				break
			}
			continue
		}
		if runIPadPending(ctx, recoveryDir, system, !cleanupPending) {
			continue
		}
		if cleanupPending {
			ipadncm.SetMonitorStatus("USB_RECOVERY_WAITING", r.Error)
			if !ipadncm.WaitForIPadSettingsRecovery(ctx) {
				break
			}
			continue
		}
		if ipadncm.UnpairedDiagnosticStartupHeld() {
			ipadncm.SetMonitorStatus("MONITOR_UNPAIRED_PREFLIGHT_PAUSED", "本候選版本暫停 iPad 自動接入以核對只讀診斷；Mac 連線保留。")
			if !ipadncm.WaitForIPadSettingsRecovery(ctx) {
				break
			}
			continue
		}
		if ipadncm.IPadModeDiagnosticHeld() {
			ipadncm.SetMonitorStatus("MONITOR_DIAGNOSTIC_PAUSED", "模式對照期間暫停普通 iPad 自動接入；Mac 連線保留")
			if !ipadncm.WaitForIPadSettingsRecovery(ctx) {
				break
			}
			continue
		}
		if !ipadncm.UnpairedExperimentCanConnect() || !ipadncm.IPadSoftwareReconnectCanConnect() || !ipadncm.NetworkOnlyCanConnect() || !ipadncm.IPadCandidateCanConnect() {
			detail := ipadncm.NetworkOnlySnapshot().Notice + " " + ipadncm.IPadCandidateSnapshot().Problem + " " + ipadncm.IPadSoftwareReconnectSnapshot().Problem
			switch ipadncm.UnpairedExperimentSnapshot().State {
			case "FINISHED":
				detail += " 本次無配對測試已結束，Apple 設定已還原，等待結果確認。"
			case "REJECTED":
				detail += " 本次無配對測試尚未開始，請查看診斷原因。"
			case "RESTORE_PENDING":
				detail += " 本次測試的 Apple 設定仍待還原，iPad 連線暫停。"
			}
			ipadncm.SetMonitorStatus("MONITOR_PAUSED", detail)
			if !ipadncm.WaitForIPadSettingsRecovery(ctx) {
				break
			}
			continue
		}
		ipadncm.SetMonitorStatus("MONITOR_WAITING", "")
		kind := ipadncm.WaitForUSBConnection(ctx)
		if kind == "iPad unpaired experiment" || kind == "iPad diagnostic" || kind == "iPad diagnostic hold" || kind == "iPad settings" || kind == "iPad candidate" || kind == "iPad software reconnect" {
			runIPadPending(ctx, recoveryDir, system, !cleanupPending)
			continue
		}
		if kind == "" {
			break
		}
		ipadncm.SetMonitorDeviceKind(kind)
		ipadncm.SetMonitorStatus("WAITING_SHARED_HOST", "")
		lease := usbhost.NewAttemptLease(ctx, usbhost.AcquireSharedHost)
		if !startupopt.Enabled(startupopt.ParallelPrepare) {
			ipadncm.RecordConnectionTimingStage("shared_host_wait_begin")
			joinError := lease.Join()
			ipadncm.RecordConnectionTimingStage("shared_host_wait_end")
			if joinError != nil {
				lease.Close()
				break
			}
			ipadncm.RecordSharedHostTiming()
		}
		ipadncm.SetMonitorStatus("MONITOR_PREPARING", "")
		if !ipadncm.ConsumeSameAttachmentRetry() || authorization == nil {
			authorization = &ipadncm.ConnectionAuthorization{}
		}
		attemptCtx, stopAttempt := lease.Context(), lease.Cancel
		clearHostJoin := ipadncm.SetSharedHostJoin(attemptCtx, lease.Join)
		softwareConsentContext.Store(&softwareConsentOwner{ctx: attemptCtx})
		authorization.BeginSecurityAttempt(attemptCtx, stopAttempt)
		ipadncm.SetConnectionContext(attemptCtx)
		r = Result{Protocol: "SUHANG-USB-EASY/2", Version: version, Started: time.Now().UTC().Format(time.RFC3339), Stage: "PREPARE", UpgradeStop: handoff, LegacyServiceRetired: retired, LegacyCleanupWarning: legacyWarning, MacRecovery: macRecovery, InstallVersionCleanup: pruned, ComponentVersion: appleComponent.Version, ComponentHash: appleComponent.Digest, Authorization: authorization, DeviceKind: kind, AppleSessionsNotRequested: true}
		ipadncm.RecordConnectionAttemptFor(kind)
		if kind == "iPad" {
			ipadncm.RecordConnectionTimingAttemptStart()
		}
		if remoteInstallID != "" {
			_ = macconnection.RecordUpgradeEvidence(recoveryDir, version, "BEGIN_"+kind+"_SESSION", "")
		}
		detachDiagnostic := ipadncm.AttachAMDSDiagnosticAttempt(stopAttempt)
		detachSoftwareReconnect := ipadncm.AttachIPadSoftwareReconnectAttempt(stopAttempt)
		if attemptCtx.Err() == nil {
			inspect(&r, system, recoveryDir)
		} else {
			r.Stage = "ATTEMPT_CANCELLED_BEFORE_USB_SETUP"
		}
		detachSoftwareReconnect()
		detachDiagnostic()

		if remoteInstallID != "" {
			problem := r.Error
			if r.Mac != nil && r.Mac.PreparationError != "" {
				problem += ": " + r.Mac.PreparationError
			}
			if problem != "" {
				_ = macconnection.RecordUpgradeEvidence(recoveryDir, version, r.Stage, problem)
			}
		}
		authorization.FinishSecurityAttempt()
		ipadncm.ClearSimplifiedIPadConnectionScope()
		hostInvalidated := lease.Invalidated()
		ipadncm.RecordConnectionArchiveEvent("owner_phase", map[string]any{"phase": "session_cancel_begin", "device_kind": kind})
		stopAttempt()
		clearHostJoin()
		softwareConsentContext.Store(nil)
		lease.Close()
		fileshare.USB.Native.Store(true)
		ipadncm.SetConnectionContext(ctx)
		if reason := authorization.SecurityFailure(); reason != "" {
			r.Error = reason
		}
		if b, e := json.Marshal(r); e != nil || attemptHistory.Add(b) != nil {
			r.AttemptHistoryError = "ATTEMPT_HISTORY_NOT_RECORDED"
		}
		unsafeCleanup := r.RebootRequired || (r.ServicePause.StopAttempted && !r.ServicePause.Restored) || (r.GroupingServicePause != nil && r.GroupingServicePause.StopAttempted && !r.GroupingServicePause.Restored) || (r.Grouping != nil && (r.Grouping.Transaction.RestoreError != "" || r.Grouping.Transaction.BackupSaved && !r.Grouping.Transaction.ConfigurationRetained && (!r.Grouping.Transaction.RestoreCompleted || !r.Grouping.Transaction.JournalCleared)))
		if r.Grouping != nil && r.Grouping.Application != nil {
			app := r.Grouping.Application
			if app.Recovery.Error != "" || app.Recovery.Pending && !app.Recovery.JournalCleared {
				unsafeCleanup = true
			}
			if r.Error == "" {
				r.Error = app.Error
				if p := r.Grouping.PeerProbe; p != nil {
					if !p.IPv6EchoVerified {
						r.Error = p.Status
					} else if !app.Consent {
						r.Error = "APPLICATION_CONNECTION_DECLINED"
					}
				}
			}
		}
		if r.Mac != nil && r.Mac.BridgeStarted && !r.Mac.CleanupConfirmed {
			unsafeCleanup = true
		}
		lastRecovery.Store(recoverySummary(r))
		ipadncm.MarkIPadSoftwareReconnectSessionCleanup(!unsafeCleanup)
		ipadncm.RecordConnectionArchiveEvent("owner_phase", map[string]any{"phase": "session_cleanup_complete", "device_kind": kind, "cleanup_safe": !unsafeCleanup})
		ipadncm.RequestConnectionEnvironmentCapture()
		if unsafeCleanup {
			cleanupPending = true
			runIPadPending(ctx, recoveryDir, system, false)
			// An iPad restoration fault must not kill the independent Mac maintenance
			// channel. Pause this device, keep the parent and Mac service resident.
			ipadncm.SetMonitorStatus("USB_RECOVERY_WAITING", r.Error)
			continue
		}
		if ctx.Err() != nil {
			break
		}
		if hostInvalidated {
			continue
		}
		applicationRan := r.Grouping != nil && r.Grouping.Application != nil && r.Grouping.Application.DHCPStarted && r.Grouping.Application.ElapsedSeconds > 0
		if r.Mac != nil && r.Mac.Ready && r.Mac.CleanupConfirmed {
			applicationRan = true
		}
		if runIPadPending(ctx, recoveryDir, system, !unsafeCleanup) {
			continue
		}
		if !ipadncm.IPadSoftwareReconnectCanConnect() || !ipadncm.IPadCandidateCanConnect() || !ipadncm.NetworkOnlyCanConnect() {
			continue
		}
		if !ipadncm.WaitAfterUSBAttempt(ctx, r.Error, applicationRan) {
			break
		}
	}
	cancel()
	// Consume idle requests with cleanupSafe=false after process cancellation;
	// Only a previously requested explicit OFF may persist its intent; no new
	// native permissions or USB operation may begin during exit.
	// The bound also prevents a late UI request from keeping shutdown alive.
	for i := 0; i < 8 && runIPadPending(ctx, recoveryDir, system, false); i++ {
	}
	if err := ipadncm.FinishIPadSoftwareReconnectOwner(ctx, recoveryDir, !cleanupPending); err != nil {
		cleanupPending = true
		r.Error = "SOFTWARE_RECONNECT_EXIT_RECOVERY_PENDING: " + err.Error()
		_, _ = save(r)
	}
	endMacJoin := shutdowntrace.Begin(shutdowntrace.PhaseMacJoin)
	<-macDone
	endMacJoin()
	if cleanupPending {
		applicationExitCleanupPending.Store(true)
	}
	if cleanupPending {
		_, _ = save(r)
		ipadncm.SetMonitorStatus("MONITOR_RECOVERY_PENDING", r.Error)
	}
	shutdowntrace.Wrap(shutdowntrace.PhaseUIStop, closeUI)()
	// Normal exit performs network cleanup only. Diagnostics remain opt-in in
	// the live UI; never archive or launch Explorer as a shutdown side effect.
	if cleanupPending && !coreProcessMode && !developerRemote.Requested() && remoteInstallID == "" {
		dialog("USB 連線已停止，但部分網路或服務清理尚未完成。下次啟動會先重試恢復。"+r.Error, 0x30)
	}
}

// The iPad owner runs fixed requests only after the previous network session
// has cleaned up. No RPC handler mutates active driver/grouping state.
func runIPadPending(ctx context.Context, dir, system string, safe bool) bool {
	if ipadncm.RunPendingIPadSoftwareReconnect(ctx, safe) {
		return true
	}
	if ipadncm.RunPendingAMDSModeDiagnostic(ctx, version, dir, safe) {
		return true
	}
	return false
}
