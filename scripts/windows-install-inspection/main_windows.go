//go:build windows && amd64

// Standalone read-only collector for incomplete legacy-installation reports.
// It never stops, starts, removes or changes a service or registry key.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"suhang/usbnet/internal/app/connectioninstall"
)

func collect() map[string]any {
	r := map[string]any{"schema": 1, "inspection": connectioninstall.InspectInstallation(), "changesMade": false}
	var problems []string
	record := func(label string, value any, err error) {
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", label, err))
		} else {
			r[label] = value
		}
	}
	defer func() { r["queryErrors"] = problems }()
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		record("serviceManager", nil, err)
		return r
	}
	defer windows.CloseServiceHandle(h)
	sh, err := windows.OpenService(h, windows.StringToUTF16Ptr(connectioninstall.CoreServiceName), windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		record("service", nil, err)
		return r
	}
	s := &mgr.Service{Name: connectioninstall.CoreServiceName, Handle: sh}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		record("serviceConfig", nil, err)
	} else {
		// Passwords are neither requested nor exported.
		r["serviceConfig"] = map[string]any{
			"binaryPathName": c.BinaryPathName, "serviceStartName": c.ServiceStartName,
			"serviceType": c.ServiceType, "startType": c.StartType, "delayedAutoStart": c.DelayedAutoStart,
			"displayName": c.DisplayName, "description": c.Description,
			"errorControl": c.ErrorControl, "sidType": c.SidType, "tagId": c.TagId,
			"loadOrderGroup": c.LoadOrderGroup, "dependencies": c.Dependencies,
		}
		args, err := windows.DecomposeCommandLine(c.BinaryPathName)
		record("serviceArguments", args, err)
	}
	actions, err := s.RecoveryActions()
	record("recoveryActions", actions, err)
	command, err := s.RecoveryCommand()
	record("recoveryCommand", command, err)
	message, err := s.RebootMessage()
	record("rebootMessage", message, err)
	flag, err := s.RecoveryActionsOnNonCrashFailures()
	record("recoveryActionsOnNonCrashFailures", flag, err)
	return r
}

func run() error {
	fmt.Println("USB Link - read-only service inspection")
	fmt.Println("No installation, service or registry changes will be made.")
	r := collect()
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Unique file; preserve every earlier report, including install-state.json.
	name := "USB-Link-service-details-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".json"
	path := filepath.Join(filepath.Dir(exe), name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(b, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	for _, err := range []error{writeErr, syncErr, closeErr} {
		if err != nil {
			return err
		}
	}
	fmt.Println("Report saved:", path)
	return nil
}

func main() {
	err := run()
	if err != nil {
		fmt.Println("Inspection could not save a report:", err)
	}
	fmt.Println("Press Enter to close.")
	fmt.Scanln()
	if err != nil {
		os.Exit(1)
	}
}
