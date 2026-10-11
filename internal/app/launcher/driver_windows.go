//go:build windows && amd64

package launcher

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/ipadncm"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Pinned, unmodified files from the Microsoft-hosted Apple driver package.
var driverFiles = map[string]string{
	"AppleUsb.inf":         "95cab1fbf0e6cd6211a6d14d75041c83c182740c39c21c5d7a4e2430bd8b1e56",
	"appleusb.cat":         "09b243b79396357d982016ad043c6102b7281eca7076e3d6593d23f65bea823d",
	"AppleLowerFilter.sys": "61c6533dadad5c47bdcf996297e69501092ffb0d1f1dcc2ac6df92e6043d5b43",
	"AppleKmdfFilter.sys":  "e044b74ff494725d56b292ace8d558e315ae406085ee3695d859ad97254897fa",
	"AppleUsbFilter.dll":   "84536890ac36f4fbcaeaef44ee38eb73123093e9253d07a6906f918b8b974ae8",
}

type DriverPreparation struct {
	Version                 string           `json:"bundled_driver_version"`
	Before                  ipadncm.Snapshot `json:"before"`
	AlreadyBound            bool             `json:"official_composite_binding_present"`
	Consent                 bool             `json:"repair_consent"`
	HashesVerified          bool             `json:"all_driver_file_hashes_verified"`
	CatalogVerified         bool             `json:"windows_catalog_signature_verified"`
	Attempted               bool             `json:"pnputil_registration_attempted"`
	Exit                    *int             `json:"pnputil_exit_code,omitempty"`
	RebootRequired          bool             `json:"reboot_required"`
	ServiceBefore           uint32           `json:"apple_service_state_before"`
	ServiceAfter            uint32           `json:"apple_service_state_after"`
	ServiceStartAttempted   bool             `json:"apple_service_start_attempted"`
	NetworkOnlyStopVerified bool             `json:"expected_network_only_service_stop_verified"`
	Error                   string           `json:"error,omitempty"`
}

func serviceState() uint32 {
	m, e := mgr.Connect()
	if e != nil {
		return 0
	}
	defer m.Disconnect()
	s, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		return 0
	}
	defer s.Close()
	state, e := s.Query()
	if e != nil {
		return 0
	}
	return uint32(state.State)
}
func ensureService(d *DriverPreparation) bool {
	m, e := mgr.Connect()
	if e != nil {
		return false
	}
	defer m.Disconnect()
	s, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		return false
	}
	defer s.Close()
	state, e := s.Query()
	if e != nil {
		return false
	}
	if state.State == svc.Stopped {
		d.ServiceStartAttempted = true
		if e = s.Start(); e != nil {
			return false
		}
	} else if state.State != svc.Running && state.State != svc.StartPending {
		return false
	}
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		state, e = s.Query()
		if e != nil {
			return false
		}
		if state.State == svc.Running {
			return true
		}
		if state.State != svc.StartPending {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
func verifyCatalog(path, system string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	script := `$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $env:SUHANG_APPLE_CAT_PATH; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match '(^|,\s*)CN=Microsoft Windows Hardware Compatibility Publisher(,|$)' -and $s.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)') { Write-Output 'VALID_DRIVER_CATALOG'; exit 0 }; exit 2`
	c := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "SUHANG_APPLE_CAT_PATH=") {
			c.Env = append(c.Env, v)
		}
	}
	c.Env = append(c.Env, "SUHANG_APPLE_CAT_PATH="+path)
	b, e := c.Output()
	return e == nil && strings.TrimSpace(string(b)) == "VALID_DRIVER_CATALOG"
}
func prepareDriver(system string) (d DriverPreparation) {
	d.Version = "486.0.0.0"
	d.ServiceBefore = serviceState()
	defer func() { d.ServiceAfter = serviceState() }()
	d.Before = ipadncm.Inspect()
	if d.Before.Error != "" || len(d.Before.Devices) != 1 || d.Before.Devices[0].PID != "12AB" {
		d.Error = "NEED_ONLY_TARGET_05AC_12AB_CONNECTED"
		return
	}
	for _, n := range d.Before.Nodes {
		if strings.EqualFold(n.IDPrefix, `USB\VID_05AC&PID_12AB`) && strings.EqualFold(n.Service, "usbccgp") && n.Problem == 0 && n.StateError == "" {
			for _, filter := range n.LowerFilters {
				if strings.EqualFold(filter, "AppleLowerFilter") {
					d.AlreadyBound = true
				}
			}
		}
	}
	// The USB filter and exact root, not AMDS runtime state, are prerequisites.
	// Full installed hash/native-root admission follows in the no-session path.
	if d.AlreadyBound {
		return
	}
	d.Consent = dialog("是否補齊／註冊蘋果官方 USB 驅動並在需要時啟動蘋果通信服務？\n\n這份未修改的 Apple USB 486.0.0.0 驅動來自微軟 Windows Update，明確支援目前的 05AC:12AB。\n\n它使用 Windows 內建的 USB 組合裝置與 WinUSB 驅動，也包含蘋果官方的 AppleLowerFilter、AppleKmdfFilter 及 AppleUsbFilter 元件。這些是蘋果官方驅動，不是 USB Link 自製驅動。\n\n會先核對全部檔案與微軟驅動目錄簽名，再由 Windows 安裝。可能短暫中斷 USB；不強制覆蓋較高優先級的驅動，不改安全設定、不自動重啟。請只連接這一台 iPad。", 0x4|0x20|0x100) == 6
	if !d.Consent {
		d.Error = "OFFICIAL_DRIVER_REPAIR_DECLINED"
		return
	}
	if !d.AlreadyBound {
		dir, e := privateStage()
		if e != nil {
			d.Error = "PRIVATE_STAGING_FAILED"
			return
		}
		defer os.RemoveAll(dir)
		for name, hash := range driverFiles {
			b, e := bundledFile("AppleUSB/" + name)
			if e != nil || fmt.Sprintf("%x", sha256.Sum256(b)) != hash {
				d.Error = "OFFICIAL_DRIVER_FILE_MISSING_OR_HASH_MISMATCH"
				return
			}
			if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
				d.Error = "DRIVER_STAGING_FAILED"
				return
			}
		}
		d.HashesVerified = true
		if !verifyCatalog(filepath.Join(dir, "appleusb.cat"), system) {
			d.Error = "WINDOWS_DRIVER_CATALOG_NOT_VERIFIED"
			return
		}
		d.CatalogVerified = true
		// PnPUtil checks catalog membership and native policy. Do not force a
		// downgrade or delete existing drivers. Do not kill it during installation.
		c := exec.Command(filepath.Join(system, "pnputil.exe"), "/add-driver", filepath.Join(dir, "AppleUsb.inf"), "/install")
		d.Attempted = true
		e = c.Run()
		if c.ProcessState == nil {
			d.Error = "PNPUTIL_LAUNCH_FAILED"
			return
		}
		exit := c.ProcessState.ExitCode()
		d.Exit = &exit
		if exit == 3010 || exit == 1641 {
			d.RebootRequired = true
			return
		}
		if e != nil || exit != 0 {
			d.Error = "OFFICIAL_DRIVER_REGISTRATION_FAILED"
			return
		}
	}
	if !ensureService(&d) {
		d.Error = "APPLE_COMMUNICATION_SERVICE_NOT_RUNNING"
	}
	return
}
