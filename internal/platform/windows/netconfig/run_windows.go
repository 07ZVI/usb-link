//go:build windows && amd64

package netconfig

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func Run(script string, l *log.Logger) error {
	return RunContext(context.Background(), script, l)
}

// Compatibility entry point; driver identity proof uses native APIs only.
func RunReadOnlySharedHostIdentity(index uint32, l *log.Logger) error {
	return VerifySharedHostIdentityNative(index)
}

func RunContext(ctx context.Context, script string, l *log.Logger) error {
	return runNetworkScript(ctx, script, l, 35*time.Second)
}

func RunLegacyRoleContext(ctx context.Context, role, script string, l *log.Logger) (err error) {
	if legacyRoleOperation(role) == "" {
		return fmt.Errorf("USB_LEGACY_SCRIPT_ROLE_INVALID")
	}
	finish := BeginLegacyRoleScriptTiming(role)
	defer func() { finish(err) }()
	return RunContext(ctx, script, l)
}

func runNetworkScript(parent context.Context, script string, l *log.Logger, limit time.Duration) (err error) {
	complete := beginNetworkTiming("legacy_network_script")
	defer func() { complete(err) }()
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", diagnosticScript(script))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	b, e := cmd.CombinedOutput()
	if strings.Contains(script, "USB-CoreSnapshot") {
		// Core result metadata is local protocol data, never log or export hashes.
		l.Printf("owned core network configuration completed=%t error=%v", e == nil, e)
	} else {
		LogNetworkScriptOutput(script, b, e, l)
	}
	if e != nil {
		code := networkScriptFailureCode(string(b))
		if ctx.Err() != nil {
			code = "TIMEOUT"
		}
		recordNetworkScriptFailure(script, code, time.Since(started))
		return fmt.Errorf("owned USB network configuration: %s", code)
	}
	if !strings.Contains(string(b), "SUHANG_NETWORK_SCRIPT_OK") {
		recordNetworkScriptFailure(script, "COMPLETION_UNCONFIRMED", time.Since(started))
		return fmt.Errorf("network script did not confirm completion")
	}
	if _, err := CompleteCorePermissionReadback(script, string(b), func(clean string) bool { return strings.Contains(clean, "SUHANG_NETWORK_SCRIPT_OK") }); err != nil {
		return fmt.Errorf("core permission readback rejected: %w", err)
	}
	return nil
}

func VerifyWintun(path string, l *log.Logger) error {
	return VerifyWintunNative(path, l)
}
