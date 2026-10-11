//go:build windows && amd64 && usblink_operator_repair

// Private operator repair; never included in USB Link's public executable.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/dependencies"
)

var installerSHA string // Build pins the reviewed installer, not a mutable manifest.

type report struct {
	StartedUTC          string              `json:"started_utc"`
	Stage               string              `json:"stage"`
	Error               string              `json:"error,omitempty"`
	Backup              string              `json:"backup,omitempty"`
	InstallerVersion    string              `json:"installer_version"`
	InstallerSHA        string              `json:"installer_sha256"`
	CoreRunningVerified bool                `json:"core_running_verified"`
	ConnectionAccepted  bool                `json:"connection_accepted"`
	Diagnostics         []map[string]string `json:"diagnostics,omitempty"`
}

func pinnedInstaller(path string) (*os.File, error) {
	if len(installerSHA) != 64 {
		return nil, errors.New("REPAIR_INSTALLER_PIN_MISSING")
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), path)
	fail := func() (*os.File, error) { f.Close(); return nil, errors.New("REPAIR_INSTALLER_HASH_OR_FILE_CHANGED") }
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return fail()
	}
	st, e := f.Stat()
	if e != nil || st.Size() < 1024 || st.Size() > 256<<20 {
		return fail()
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, 256<<20+1))
	if e != nil || n != st.Size() || hex.EncodeToString(hash.Sum(nil)) != installerSHA {
		return fail()
	}
	return f, nil // Hold a read-only handle denying write/delete through launch.
}

// Extract only bounded stage/error fields, never the full hardware/credential
// diagnostic archive. Both installer and service can explain startup failure.
func startupDiagnostics(start time.Time) []map[string]string {
	system, e := windows.GetSystemWindowsDirectory()
	if e != nil {
		return nil
	}
	patterns := []string{filepath.Join(system, "Temp", "Suhang-iPad-Grouping-Recovery", "core-diagnostics", "0.9.5", "*", "*.zip")}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		patterns = append(patterns, filepath.Join(base, "Suhang", "iPadUSBSetup", "0.9.5", "*", "*.zip"))
	}
	var results []map[string]string
	for _, pattern := range patterns {
		paths, _ := filepath.Glob(pattern)
		for i := len(paths) - 1; i >= 0 && len(results) < 8; i-- {
			path := paths[i]
			st, e := os.Lstat(path)
			if e != nil || !st.Mode().IsRegular() || st.Size() > 8<<20 || st.ModTime().Before(start.Add(-5*time.Second)) {
				continue
			}
			z, e := zip.OpenReader(path)
			if e != nil {
				continue
			}
			for _, entry := range z.File {
				if entry.Name != "ipad-usb-easy.json" || entry.UncompressedSize64 > 2<<20 {
					continue
				}
				f, e := entry.Open()
				if e != nil {
					continue
				}
				b, e := io.ReadAll(io.LimitReader(f, 2<<20+1))
				f.Close()
				var fields struct {
					Version string `json:"version"`
					Stage   string `json:"stage"`
					Error   string `json:"error"`
				}
				if e == nil && len(b) <= 2<<20 && json.Unmarshal(b, &fields) == nil && fields.Version == "0.9.5" {
					if len(fields.Error) > 2048 {
						fields.Error = fields.Error[:2048]
					}
					if len(fields.Stage) > 128 {
						fields.Stage = fields.Stage[:128]
					}
					results = append(results, map[string]string{"stage": fields.Stage, "error": fields.Error})
				}
			}
			z.Close()
		}
	}
	return results
}

func run() (err error) {
	checkOnly := len(os.Args) == 2 && os.Args[1] == "--check-only"
	if len(os.Args) != 1 && !checkOnly || !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("Run repair-and-install.bat and accept administrator elevation.")
	}
	if checkOnly {
		if e := connectioninstall.InspectReportedDeletedInstallation(); e != nil {
			return e
		}
		fmt.Println("Exact reported residual state verified. No Windows settings changed.")
		return nil
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	base := filepath.Dir(exe)
	logDir := filepath.Join(base, "logs")
	if e = os.MkdirAll(logDir, 0700); e != nil {
		return e
	}
	start := time.Now()
	r := report{StartedUTC: start.UTC().Format(time.RFC3339), Stage: "checking", InstallerVersion: "0.9.5", InstallerSHA: installerSHA}
	writeReport := func() error {
		b, e := json.MarshalIndent(r, "", "  ")
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(logDir, "reinstall-result.json"), append(b, '\n'), 0600)
	}
	defer func() {
		if err != nil {
			r.Error = err.Error()
		}
		r.Diagnostics = startupDiagnostics(start)
		if e := writeReport(); err == nil {
			err = e
		}
	}()
	installer := filepath.Join(base, "USB-Link-0.9.5-windows-x64.exe")
	file, e := pinnedInstaller(installer)
	if e != nil {
		return e
	}
	defer file.Close()
	root, e := connectioninstall.DependencyDirectory()
	if e != nil {
		return e
	}
	p := &dependencies.WindowsPlatform{RootPath: connectioninstall.DependencyDirectory, Safe: connectioninstall.VerifyDependencyPath}
	// .NET and Wintun must be verified locally before removing either residual.
	for _, id := range []string{"dotnet", "wintun"} {
		a, e := dependencies.Lookup(id)
		if e != nil {
			return e
		}
		if _, ready := p.Detect(a, root); !ready {
			return fmt.Errorf("REPAIR_COMPONENT_NOT_READY: %s; run the supplied offline preparation first", id)
		}
	}
	r.Stage = "repairing_exact_deleted_install"
	if e = writeReport(); e != nil {
		return e
	}
	fmt.Println("Checking deleted 0.8.139 registration and stopped 0.9.3 core. Saving backup before removal.")
	r.Backup, e = connectioninstall.RepairReportedDeletedInstallation()
	if e != nil {
		return e
	}
	fmt.Println("Residual repair completed. Backup:", r.Backup)
	r.Stage = "starting_installer"
	if e = writeReport(); e != nil {
		return e
	}
	child := exec.Command(installer)
	if e = child.Start(); e != nil {
		return e
	}
	child.Process.Release()
	r.Stage = "waiting_for_verified_core"
	if e = writeReport(); e != nil {
		return e
	}
	fmt.Println("Installing 0.9.5; waiting for verified registration, binding and running service. Keep this window open.")
	deadline := time.Now().Add(5 * time.Minute)
	stable := 0
	var last error
	for time.Now().Before(deadline) {
		last = connectioninstall.ObserveReinstalledCore(installerSHA)
		if last == nil {
			stable++
		} else {
			stable = 0
		}
		if stable >= 5 {
			r.Stage, r.CoreRunningVerified = "core_running_verified", true
			r.Diagnostics = startupDiagnostics(start)
			for _, diagnostic := range r.Diagnostics {
				if diagnostic["error"] != "" {
					r.Stage = "core_running_with_startup_problem"
					return fmt.Errorf("REINSTALL_STARTUP_PROBLEM: %s: %s", diagnostic["stage"], diagnostic["error"])
				}
			}
			fmt.Println("0.9.5 core is verified and running. USB/SMB still require device acceptance.")
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	r.Stage = "installation_not_verified"
	return fmt.Errorf("REINSTALL_NOT_VERIFIED: %v; review logs/reinstall-result.json and any Windows message", last)
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "FAILED:", strings.TrimSpace(e.Error()))
		os.Exit(1)
	}
}
