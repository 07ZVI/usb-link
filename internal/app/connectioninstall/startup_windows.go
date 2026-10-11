//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

var startupTaskLock sync.Mutex

// ReadStartupTaskState performs a fresh read-only query. It never registers,
// starts or removes a task and is not intended for periodic UI polling.
func ReadStartupTaskState(path string) (StartupTaskObservation, error) {
	return runStartupTaskMode(context.Background(), "QUERY", path)
}

func SetStartupContext(ctx context.Context, enabled bool, path string) error {
	mode := "OFF"
	if enabled {
		mode = "ON"
	}
	_, e := runStartupTaskMode(ctx, mode, path)
	return e
}

type startupOutputBuffer struct{ bytes.Buffer }

func (b *startupOutputBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if left := 4096 - b.Len(); left > 0 {
		_, _ = b.Buffer.Write(p[:min(n, left)])
	}
	return n, nil
}

func runStartupTaskMode(parent context.Context, mode, path string) (result StartupTaskObservation, err error) {
	if parent == nil {
		return StartupTaskObservation{Code: "STARTUP_CONTEXT_UNAVAILABLE"}, errors.New("STARTUP_CONTEXT_UNAVAILABLE")
	}
	startupTaskLock.Lock()
	defer startupTaskLock.Unlock()
	started := time.Now()
	result = StartupTaskObservation{Code: "STARTUP_PREFLIGHT_FAILED", Phase: "QUERY"}
	defer func() { result.DurationMS = time.Since(started).Milliseconds(); recordStartupTaskObservation(result) }()
	if parent.Err() != nil {
		result.Code = "STARTUP_CANCELLED"
		return result, errors.New(result.Code)
	}
	if mode != "ON" && mode != "OFF" && mode != "QUERY" {
		result.Code = "STARTUP_MODE_INVALID"
		return result, errors.New(result.Code)
	}
	if Verify(path) != nil {
		result.Code = "STARTUP_EXECUTABLE_UNVERIFIED"
		return result, errors.New(result.Code)
	}
	if nativeStartupEnabled.Load() {
		user, tokenError := windows.GetCurrentProcessToken().GetTokenUser()
		if tokenError != nil {
			result.Code = "STARTUP_TOKEN_UNAVAILABLE"
			return result, errors.New(result.Code)
		}
		if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
			self, selfError := os.Executable()
			if selfError != nil {
				result.Code = "STARTUP_EXECUTABLE_UNVERIFIED"
				return result, errors.New(result.Code)
			}
			if _, ownerError := ActivateCoreOwner(self); ownerError != nil {
				result.Code = "STARTUP_TOKEN_UNAVAILABLE"
				return result, errors.New(result.Code)
			}
		}
	}
	name, sid, e := taskIdentity()
	if e != nil {
		result.Code = "STARTUP_TOKEN_UNAVAILABLE"
		return result, errors.New(result.Code)
	}
	root, e := Root()
	if e != nil {
		result.Code = "STARTUP_ROOT_UNAVAILABLE"
		return result, errors.New(result.Code)
	}
	legacy, e := legacyRoot()
	if e != nil {
		result.Code = "STARTUP_ROOT_UNAVAILABLE"
		return result, errors.New(result.Code)
	}
	xmlText, e := TaskXML(path, sid)
	if e != nil {
		result.Code = "STARTUP_XML_INVALID"
		return result, errors.New(result.Code)
	}
	if nativeStartupEnabled.Load() {
		return runNativeStartupTask(parent, mode, path, name, sid, xmlText)
	}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		result.Code = "STARTUP_SYSTEM_DIRECTORY_UNAVAILABLE"
		return result, errors.New(result.Code)
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", startupTaskScript)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "SUHANG_") {
			c.Env = append(c.Env, v)
		}
	}
	c.Env = append(c.Env, "SUHANG_LEGACY_ROOT="+legacy, "SUHANG_LEGACY_TASK_NAME="+strings.Replace(name, "USB-Link-", "Suhang-iPad-USB-", 1), "SUHANG_STARTUP_MODE="+mode, "SUHANG_TASK_NAME="+name, "SUHANG_SID="+sid, "SUHANG_ROOT="+root, "SUHANG_PRODUCT="+ProductID, "SUHANG_TASK_XML="+xmlText, "SUHANG_EXE="+path)
	var output, stderr startupOutputBuffer
	c.Stdout = &output
	c.Stderr = &stderr
	processError := c.Run()
	if ctx.Err() != nil {
		result.Code = "STARTUP_TIMEOUT"
		if parent.Err() != nil {
			result.Code = "STARTUP_CANCELLED"
		}
		return result, errors.New(result.Code)
	}
	result, err = parseStartupTaskObservation(output.Bytes(), processError != nil)
	if err == nil && ((mode == "ON" && (!result.Enabled || result.TaskCount != 1)) || (mode == "OFF" && result.TaskCount != 0)) {
		result.Available = false
		result.Enabled = false
		result.Code = "STARTUP_READBACK_CHANGED"
		err = fmt.Errorf("%s", result.Code)
	}
	return result, err
}
