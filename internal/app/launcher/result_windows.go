//go:build windows && amd64

package launcher

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/ipadeasy"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/platform/windows/machinepaths"
	"suhang/usbnet/internal/security/applelease"
	"time"
)

type Result struct {
	InstallationDetail        string                           `json:"installation_error_detail,omitempty"`
	FlowMeasurement           any                              `json:"native_flow_measurement,omitempty"`
	DeveloperUpdate           any                              `json:"developer_update,omitempty"`
	UpgradeStop               *connectioninstall.UpgradeStop   `json:"previous_program_handoff,omitempty"`
	LegacyServiceRetired      bool                             `json:"legacy_service_retired"`
	LegacyCleanupWarning      string                           `json:"legacy_files_preserved_reason,omitempty"`
	LegacyMigrationError      string                           `json:"legacy_service_migration_error,omitempty"`
	MacRecovery               macconnection.RecoveryReport     `json:"previous_mac_recovery"`
	HostEarlyRecovery         *earlyHostRecoveryReport         `json:"early_interrupted_host_recovery,omitempty"`
	AttemptHistoryError       string                           `json:"attempt_history_error,omitempty"`
	DeviceKind                string                           `json:"device_kind,omitempty"`
	Mac                       *macconnection.Result            `json:"mac_connection,omitempty"`
	AppleSessionsNotRequested bool                             `json:"apple_pairing_and_metadata_sessions_not_requested"`
	MonitorDiagnostics        ipadncm.MonitorDiagnostics       `json:"resident_monitor_observations"`
	InstallVersionCleanup     []string                         `json:"previous_owned_versions_preserved_reason,omitempty"`
	Authorization             *ipadncm.ConnectionAuthorization `json:"connection_authorization,omitempty"`
	ApplicationRecovery       ipadncm.ApplicationRecovery      `json:"previous_application_recovery"`
	Protocol                  string                           `json:"protocol"`
	Version                   string                           `json:"version"`
	Started                   string                           `json:"started_utc"`
	Stage                     string                           `json:"stage"`
	Error                     string                           `json:"error,omitempty"`
	ComponentVersion          string                           `json:"apple_component_version"`
	ComponentHash             string                           `json:"apple_component_sha256"`
	AlreadyInstalled          bool                             `json:"apple_service_present_before"`
	AppleServicePresent       bool                             `json:"apple_service_present_after"`
	InstallConsent            bool                             `json:"install_consent"`
	HashVerified              bool                             `json:"component_hash_verified"`
	SignatureVerified         bool                             `json:"windows_apple_signature_verified"`
	InstallerExit             *int                             `json:"installer_exit_code,omitempty"`
	RebootRequired            bool                             `json:"reboot_required"`
	Probe                     *ipadncm.Result                  `json:"ncm_check,omitempty"`
	USBDriver                 *DriverPreparation               `json:"official_usb_driver,omitempty"`
	Workflow                  ipadeasy.Report                  `json:"workflow"`
	ServicePause              applelease.Report                `json:"apple_service_pause"`
	Startup                   *ipadncm.StartupResult           `json:"native_start_check,omitempty"`
	Recovery                  ipadncm.GroupingRecovery         `json:"previous_grouping_recovery"`
	Grouping                  *ipadncm.GroupingResult          `json:"temporary_grouping_trial,omitempty"`
	GroupingServicePause      *applelease.Report               `json:"grouping_mode_service_pause,omitempty"`
}

func save(r Result) (string, error) {
	r.FlowMeasurement = ipadncm.FlowSnapshot()
	if developerRemote != nil {
		r.DeveloperUpdate = developerRemote.Snapshot()
	}
	r.MonitorDiagnostics = ipadncm.ConnectionMonitorDiagnostics()
	var parent string
	if coreProcessMode {
		if dir, ok := serviceDiagnosticDirectory.Load().(string); ok && dir != "" {
			parent = filepath.Join(dir, "core-diagnostics", version)
		}
	} else if root, _, e := machinepaths.UIDiagnostics(); e == nil {
		parent = filepath.Join(root, version)
	}
	if parent == "" {
		return "", fmt.Errorf("no verified diagnostic directory")
	}
	if e := os.MkdirAll(parent, 0700); e != nil {
		return "", e
	}
	dir, e := os.MkdirTemp(parent, time.Now().Format("20060102-150405")+"-")
	if e != nil {
		return "", e
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return "", e
	}
	path := filepath.Join(dir, "USB連線診斷資料.zip")
	f, e := os.Create(path)
	if e != nil {
		return "", e
	}
	z := zip.NewWriter(f)
	entry, e := z.Create("ipad-usb-easy.json")
	if e == nil {
		_, e = entry.Write(append(b, '\n'))
	}
	if e == nil {
		history, er := json.MarshalIndent(attemptHistory.Snapshot(), "", "  ")
		if er != nil {
			e = er
		} else {
			var entryWriter interface{ Write([]byte) (int, error) }
			entryWriter, e = z.Create("attempt-history.json")
			if e == nil {
				_, e = entryWriter.Write(history)
			}
		}
	}
	ze, fe := z.Close(), f.Close()
	if e != nil {
		return "", e
	}
	if ze != nil {
		return "", ze
	}
	if fe != nil {
		return "", fe
	}
	return path, nil
}
func installationFailure(r *Result, stage, message string) {
	r.Stage = stage
	r.Error = stage
	r.InstallationDetail = message
	path, e := save(*r)
	if e == nil {
		writeNotices(filepath.Dir(path))
		message += "\n\n診斷資料：" + path
	}
	dialog(message, 0x10)
	if e == nil {
		system, err := windows.GetSystemDirectory()
		if err == nil {
			exec.Command(filepath.Join(system, "..", "explorer.exe"), "/select,"+path).Start()
		}
	}
}
