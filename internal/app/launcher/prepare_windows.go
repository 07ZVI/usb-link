//go:build windows && amd64

package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/coreprompt"
	"suhang/usbnet/internal/dependencies"
	"time"
	"unsafe"
)

func servicePresent() bool {
	m, e := mgr.Connect()
	if e != nil {
		return false
	}
	defer m.Disconnect()
	s, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		return false
	}
	s.Close()
	return true
}
func privateStage() (string, error) {
	w, e := windows.GetWindowsDirectory()
	if e != nil {
		return "", e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return "", e
	}
	p := filepath.Join(w, "Temp", "Suhang-iPad-USB-"+hex.EncodeToString(nonce[:]))
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		return "", e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	ptr, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return "", e
	}
	if e = windows.CreateDirectory(ptr, &sa); e != nil {
		return "", e
	}
	return p, nil
}
func verify(path, system string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	script := `$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $env:SUHANG_APPLE_MSI_PATH; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match '(^|,\s*)CN=Apple Inc\.(,|$)' -and $s.SignerCertificate.Subject -match '(^|,\s*)O=Apple Inc\.(,|$)') { Write-Output 'VALID_APPLE_SIGNATURE'; exit 0 }; exit 2`
	c := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	for _, env := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(env), "SUHANG_APPLE_MSI_PATH=") {
			c.Env = append(c.Env, env)
		}
	}
	c.Env = append(c.Env, "SUHANG_APPLE_MSI_PATH="+path)
	b, e := c.Output()
	return e == nil && strings.TrimSpace(string(b)) == "VALID_APPLE_SIGNATURE"
}
func prepare(r *Result, system string) {
	defer func() { r.AppleServicePresent = servicePresent() }()
	r.AlreadyInstalled = servicePresent()
	if !r.AlreadyInstalled {
		r.Stage = "INSTALL_CONSENT"
		if coreProcessMode {
			owner := liveCore.Load()
			if owner == nil {
				r.Error = "CORE_DEPENDENCY_UI_UNAVAILABLE"
				return
			}
			answer, e := prompts.Ask(owner.appCtx, coreprompt.Question{Dependency: "apple-support", Title: "iPad · Apple 通信元件", Body: "這台電腦尚未找到 Apple Mobile Device Service。\n\n是否自動下載並啟動蘋果官方安裝程式？\n\n官方安裝包可能同時安裝 iTunes；請在官方畫面確認所需元件。USB 驅動會另外確認。它不安裝 VPN，不降低安全設定。\n安裝前會檢查檔案雜湊與 Windows 的蘋果簽名。\n\n接著會開啟蘋果官方安裝畫面，請閱讀並依你的意願同意其授權條款。之後可在 Windows 的「已安裝的應用程式」卸載 Apple Mobile Device Support。", Accept: "下載並開啟官方安裝程式"})
			r.InstallConsent = e == nil && answer.Accepted
		} else {
			r.InstallConsent = dialog("這台電腦尚未找到 Apple Mobile Device Service。\n\n是否自動下載並啟動蘋果官方安裝程式？\n\n官方安裝包可能同時安裝 iTunes；請在官方畫面確認所需元件。USB 驅動會另外確認。它不安裝 VPN，不降低安全設定。\n安裝前會檢查檔案雜湊與 Windows 的蘋果簽名。\n\n接著會開啟蘋果官方安裝畫面，請閱讀並依你的意願同意其授權條款。之後可在 Windows 的「已安裝的應用程式」卸載 Apple Mobile Device Support。", 0x4|0x20|0x100) == 6
		}

		if !r.InstallConsent {
			r.Error = "INSTALL_DECLINED"
			return
		}
		r.Stage = "COMPONENT_VALIDATION"
		r.Stage = "OFFICIAL_APPLE_DOWNLOAD_AND_INSTALL"
		var installError error
		if coreProcessMode {
			a, _ := dependencies.Lookup("apple-support")
			root, e := dependencies.Default.Platform.Root()
			if e != nil {
				installError = e
			} else if _, ok := dependencies.Default.Platform.Detect(a, root); !ok {
				installError = fmt.Errorf("DEPENDENCY_INTERACTIVE_INSTALL_READBACK_FAILED")
			}
		} else {
			installError = dependencies.WithProgress(ctxForInstall(), func(c context.Context) error { _, e := dependencies.Ensure(c, "apple-support"); return e })
		}
		if coreProcessMode && installError == nil {
			dependencies.Default.Refresh()
		}
		if installError != nil {
			r.Error = installError.Error()
			r.RebootRequired = strings.Contains(r.Error, "REBOOT_REQUIRED")
			return
		}

	}
	r.AppleServicePresent = servicePresent()
	if !r.AppleServicePresent {
		r.Error = "APPLE_SERVICE_STILL_UNAVAILABLE"
		return
	}
	r.Stage = "OFFICIAL_USB_DRIVER"
	d := prepareDriver(system)
	r.USBDriver = &d
	if d.Error != "" {
		r.Error = d.Error
		return
	}
	if d.RebootRequired {
		r.RebootRequired = true
		r.Error = "REBOOT_REQUIRED_BEFORE_RETEST"
		return
	}
	// Existing installations proceed without a needless cable reconnect.
	if !r.AlreadyInstalled || d.Attempted {
		r.Stage = "CONNECT_AFTER_PREPARATION"
		if dialog("元件準備已完成。\n\n請確認這台 iPad 已連接 Windows、解鎖；如果尚未被識別，將線拔下再插回。USB 網路不需要「信任此電腦」；若出現該提示，請選擇「不信任」。\n\n按「確定」後，這個程式會自行接續模式切換和網卡啟動檢查，不需要執行其他版本。", 0x1|0x40|0x100) != 1 {
			r.Error = "CONNECTION_PREPARATION_CANCELLED"
			return
		}
	}
	r.Stage = "PREREQUISITES_READY"
}
