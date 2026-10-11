//go:build windows && amd64

package hostsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"suhang/usbnet/internal/security/securitypolicy"
	"syscall"
	"time"
)

// QueryFirewall is interactive metadata only, not USB admission evidence.
// Session0 service startup must not launch PowerShell for UI observations.
// Keeping that observation unknown does not skip the separate exact USB rule
// and gateway verification. A local INetFwPolicy2 observation is not used as
// an equivalent to effective ActiveStore policy, which can include GPO.
func QueryFirewall(parent context.Context) securitypolicy.Evidence {
	if parent == nil || parent.Err() != nil {
		return FirewallEvidence(nil)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return FirewallEvidence(nil)
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return securitypolicy.Evidence{State: securitypolicy.Unknown, Code: "HOST_FIREWALL_INTERACTIVE_OBSERVATION_ONLY", Scope: "host"}
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	system := os.Getenv("SystemRoot")
	if !filepath.IsAbs(system) {
		return FirewallEvidence(nil)
	}
	script := `$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,@{Name='Enabled';Expression={[bool]$_.Enabled}},@{Name='DefaultInboundAction';Expression={[string]$_.DefaultInboundAction}}) | ConvertTo-Json -Compress`
	cmd := exec.CommandContext(ctx, filepath.Join(system, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	b, err := cmd.Output()
	if err != nil || len(b) > 8192 {
		return FirewallEvidence(nil)
	}
	var profiles []FirewallProfile
	if json.Unmarshal(bytes.TrimSpace(b), &profiles) != nil {
		return FirewallEvidence(nil)
	}
	return FirewallEvidence(profiles)
}
