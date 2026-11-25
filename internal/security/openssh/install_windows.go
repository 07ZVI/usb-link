//go:build windows && amd64

package openssh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const PackageVersion = "10.4.0.0p1-Preview"
const PackageName = "OpenSSH-Win64-v10.4.0.0.msi"
const PackageURL = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/" + PackageVersion + "/" + PackageName
const PackageSHA256 = "788d8643464a01eb63640a2fd746f9ed23d106b5a901a35f88dc8cd40e446ac9"
const maxPackage = 16 << 20

// A fixed official package, not a generic elevated installer endpoint. Both
// paths require the pinned release hash and Windows Authenticode validation.
func InstallPackage(ctx context.Context, source string) error {
	s, err := Query(ctx, "refresh", "")
	if err != nil {
		return err
	}
	if s.Installed {
		return fmt.Errorf("已安裝 SSH 服務，不會混裝另一套 OpenSSH。")
	}
	var reader io.ReadCloser
	if source == "" {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, PackageURL, nil)
		if e != nil {
			return e
		}
		client := &http.Client{Timeout: 5 * time.Minute}
		resp, e := client.Do(req)
		if e != nil {
			return fmt.Errorf("下載失敗，可改用離線安裝包：%w", e)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("官方下載回覆 HTTP %d。", resp.StatusCode)
		}
		reader = resp.Body
	} else {
		f, e := os.Open(source)
		if e != nil {
			return e
		}
		reader = f
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maxPackage+1))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if len(data) > maxPackage || hex.EncodeToString(digest[:]) != PackageSHA256 {
		return fmt.Errorf("安裝包與官方 %s 不符。請選擇 %s。", PackageVersion, PackageName)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(system), "Temp", "USBLink-OpenSSH-"+hex.EncodeToString(nonce[:]))
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	dp, _ := windows.UTF16PtrFromString(dir)
	if err = windows.CreateDirectory(dp, &sa); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, PackageName)
	if err = os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	_, err = powershell(ctx, installScript, map[string]string{"path": path, "sha256": PackageSHA256})
	return err
}

const installScript = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$r=[Console]::In.ReadToEnd() | ConvertFrom-Json
if(Get-Service sshd -ErrorAction SilentlyContinue){throw '已存在 SSH 服務，安裝已取消。'}
if((Get-FileHash -LiteralPath $r.path -Algorithm SHA256).Hash -ine $r.sha256){throw '安裝包完整性核對失敗。'}
$sig=Get-AuthenticodeSignature -LiteralPath $r.path
if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw '無法驗證安裝包的 Microsoft 數位簽章。'}
$process=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/i',('"'+$r.path+'"'),'ADDLOCAL=Server','/qn','/norestart') -PassThru
$process.WaitForExit()
if($process.ExitCode -notin @(0,3010)){throw ('OpenSSH 安裝失敗，Windows Installer 代碼 '+$process.ExitCode)}
if(!(Get-Service sshd -ErrorAction SilentlyContinue)){throw '安裝程序已結束，但未找到 SSH 服務。'}
if($process.ExitCode -eq 3010){throw '安裝完成，需要重新啟動 Windows；重啟後請重新整理。'}
Write-Output 'installed'
`
