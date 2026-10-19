//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
)

var environmentCaptureRequests = make(chan struct{}, 1)

var environmentObservedPIDs = struct {
	sync.Mutex
	values  map[uint32]struct{}
	omitted uint64
}{values: make(map[uint32]struct{})}

var environmentObservedPNP struct {
	sync.Mutex
	seen bool
	hash [32]byte
}

// Preserve every changed full PnP observation before the small UI projection.
func RecordConnectionEnvironmentPNP(snapshot any) {
	environmentObservedPNP.Lock()
	defer environmentObservedPNP.Unlock()
	if !connectionTimingMasterEnabled() {
		environmentObservedPNP.seen = false
		return
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		RecordConnectionArchiveEvent("trust_event", map[string]any{"kind": "full_pnp_serialization_failed"})
		return
	}
	hash := sha256.Sum256(b)
	if environmentObservedPNP.seen && hash == environmentObservedPNP.hash {
		return
	}
	if RecordConnectionArchiveEventAccepted("trust_event", map[string]any{"kind": "full_pnp_observation", "snapshot": json.RawMessage(b)}) {
		environmentObservedPNP.hash, environmentObservedPNP.seen = hash, true
	}
}

func RecordConnectionEnvironmentPID(pid uint32) {
	if pid == 0 {
		return
	}
	environmentObservedPIDs.Lock()
	_, found := environmentObservedPIDs.values[pid]
	if !found {
		if len(environmentObservedPIDs.values) < 64 {
			environmentObservedPIDs.values[pid] = struct{}{}
		} else {
			environmentObservedPIDs.omitted++
		}
	}
	environmentObservedPIDs.Unlock()
	if !found {
		RequestConnectionEnvironmentCapture()
	}
}

// A request never queries the system on the connection or native callback thread.
func RequestConnectionEnvironmentCapture() {
	select {
	case environmentCaptureRequests <- struct{}{}:
	default:
	}
}

func StartConnectionEnvironment(ctx context.Context, version string) func() {
	run, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var enabled bool
		var last time.Time
		var files any
		for {
			requested := false
			select {
			case <-run.Done():
				return
			case <-environmentCaptureRequests:
				requested = true
			case <-ticker.C:
			}
			on := connectionTimingMasterEnabled()
			if !on {
				enabled = false
				continue
			}
			if !enabled || requested || time.Since(last) >= 10*time.Second {
				if files == nil {
					files = connectionEnvironmentFiles()
				}
				sampleCtx, stop := context.WithTimeout(run, 3*time.Second)
				r := collectConnectionEnvironment(sampleCtx, version, files)
				stop()
				if run.Err() == nil && connectionTimingMasterEnabled() {
					RecordConnectionArchiveEvent("environment_baseline", r)
				}
				last, enabled = time.Now(), true
			}
		}
	}()
	return cancel
}

func collectConnectionEnvironment(ctx context.Context, version string, files any) map[string]any {
	start := time.Now()
	run, ms := trustDiagnostics.stamp(start)
	v := windows.RtlGetVersion()
	_, bias := start.Zone()
	r := map[string]any{
		"schema": 1, "core_version": version,
		"build":                     map[string]any{"local_diagnostics": buildinfo.LocalDiagnostics == "true", "local_remote": buildinfo.LocalRemote, "go": runtime.Version(), "architecture": runtime.GOARCH, "files": files},
		"windows":                   map[string]any{"major": v.MajorVersion, "minor": v.MinorVersion, "build": v.BuildNumber, "product_type": v.ProductType, "suite_mask": v.SuiteMask},
		"clock":                     map[string]any{"sample_started_utc": start.UTC().Format(time.RFC3339Nano), "run_id": run, "observer_ms": ms, "utc_offset_seconds": bias, "uptime": connectionEnvironmentUptime(), "utc_is_host_reported_not_synchronized_with_mac": true},
		"process":                   connectionEnvironmentProcesses(ctx),
		"apple_service":             connectionEnvironmentServices(ctx),
		"system_load":               connectionEnvironmentSystemLoad(),
		"power":                     connectionEnvironmentPower(),
		"runtime_network":           RuntimeNetworkDiagnostics(),
		"network_operations":        map[string]any{"native_operations": netconfig.NativeOperationTimingsSnapshot(), "interface_operations": interfaceconfig.ObservationsSnapshot(), "firewall_shadow": netconfig.FirewallShadowDiagnostics(), "firewall_failures": netconfig.ResidentFirewallFailureDiagnostics()},
		"application":               connectionEnvironmentApplication(),
		"trust_observer":            TrustDiagnosticsSnapshot(),
		"monitor_counters":          connectionEnvironmentMonitorCounters(),
		"experiments":               map[string]any{"debug": DeveloperDebugDiagnostics(), "detection": ConnectionTimingDiagnostics(), "photo_isolation": PhotoIsolationDiagnostics(), "photo_policy": LocalPhotoPolicyDiagnostics(), "ncm_direct": LocalNCMDirectDiagnostics(), "amds_hold": LocalAMDSHoldDiagnostics(), "mac_mtu_cap": LocalMacMTUCapDiagnostics(), "wpd": localWPDTrace.snapshot()},
		"default_network_isolation": DefaultNetworkIsolationDiagnostics(),
		"trust_prompt":              TrustPromptDiagnostics(),
		"native_usb_metadata":       desktopUSBTraceSummary(LocalUSBTraceDiagnostics()),
		"native_pnp_metadata":       desktopUSBTraceSummary(LocalPnPTraceDiagnostics()),
		"grouping":                  GroupingReceiptDiagnostics(),
		"completeness":              map[string]any{"scope": "windows_usb_connection_environment", "snapshot_is_not_atomic": true, "snapshot_reads_do_not_open_usb_or_pair": true, "ipad_trust_ui_observable": false, "ipad_accessory_authorization_observable": false, "ipad_internal_trust_cache": "not_exposed_by_windows", "wpd_device_attribution": "unproven", "process_name_does_not_prove_request_initiator": true},
	}
	if ctx.Err() == nil {
		r["pnp"] = inventoryPnP(ctx)
	} else {
		r["pnp"] = map[string]any{"error": "ENVIRONMENT_CAPTURE_BUDGET_EXCEEDED"}
	}
	r["sample_finished_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	r["elapsed_ms"] = time.Since(start).Milliseconds()
	r["budget_exceeded"] = ctx.Err() != nil
	return r
}

func connectionEnvironmentMonitorCounters() any {
	s := ConnectionMonitorDiagnostics()
	s.ConnectionTrace = nil
	s.NoticeSamples = nil
	return map[string]any{"counters": s, "compact_ring_omissions_are_not_archive_loss": true}
}

func connectionEnvironmentApplication() any {
	state := deviceMonitor("iPad")
	if state == nil {
		return map[string]any{"status": "no_ipad_session"}
	}
	r := state.snapshot()
	return map[string]any{"status": r.Status, "error": r.Error, "dhcp_started": r.DHCPStarted, "dhcp_acks": r.DHCPACKs, "dhcp_error": r.DHCPError, "peer_ipv4_verified": r.PeerIPv4NeighborVerified, "http_verified": r.HTTPVerified, "sunshine_tcp_observed": r.SunshineClientTCPObserved, "mdns_registered": r.MDNSRegistered, "mdns_error": r.MDNSError, "cleanup": r.Recovery, "counter_semantics": "protocol_observations_not_application_acceptance"}
}

func environmentReadError(err error) string {
	status := trustWindowsReadCode(err)
	var code syscall.Errno
	if errors.As(err, &code) && code != 0 {
		return fmt.Sprintf("%s_win32_%d", status, uint32(code))
	}
	return status
}

func connectionEnvironmentFiles() any {
	start := time.Now()
	exe, err := os.Executable()
	if err != nil {
		return map[string]any{"status": "current_executable_unavailable"}
	}
	files := map[string]any{
		"scope":                "fixed_candidates_not_installation_verification",
		"current_process":      environmentFileIdentity(exe),
		"desktop_adjacent":     environmentFileIdentity(filepath.Join(filepath.Dir(exe), "USBLink.Desktop.exe")),
		"desktop_subdirectory": environmentFileIdentity(filepath.Join(filepath.Dir(exe), "desktop", "USBLink.Desktop.exe")),
	}
	files["sample_started_utc"] = start.UTC().Format(time.RFC3339Nano)
	files["sample_finished_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	files["elapsed_ms"] = time.Since(start).Milliseconds()
	files["cached_once_per_worker"] = true
	return files
}

func environmentFileIdentity(path string) any {
	r := map[string]any{"status": "unavailable"}
	s, err := os.Lstat(path)
	if err != nil {
		r["status"] = environmentReadError(err)
		return r
	}
	if !s.Mode().IsRegular() || s.Size() > 64*1024*1024 {
		r["status"] = "not_a_bounded_regular_file"
		return r
	}
	f, err := os.Open(path)
	if err != nil {
		r["status"] = environmentReadError(err)
		return r
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 64*1024*1024+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || n != s.Size() || !s.ModTime().Equal(after.ModTime()) {
		r["status"] = "read_failed_or_changed"
		return r
	}
	r["status"], r["bytes"], r["sha256"] = "read_ok", n, hex.EncodeToString(h.Sum(nil))
	return r
}

func connectionEnvironmentServices(ctx context.Context) any {
	r := map[string]any{}
	m, err := mgr.Connect()
	if err != nil {
		return map[string]any{"query_status": environmentReadError(err)}
	}
	defer m.Disconnect()
	for _, name := range []string{"Apple Mobile Device Service", "Bonjour Service", "WPDBusEnum", "ShellHWDetection", "stisvc"} {
		if ctx.Err() != nil {
			r[name] = map[string]any{"query_status": "budget_exceeded"}
			continue
		}
		s, err := m.OpenService(name)
		if err != nil {
			r[name] = map[string]any{"query_status": environmentReadError(err)}
			continue
		}
		row := map[string]any{}
		status, err := s.Query()
		row["query_status"] = environmentReadError(err)
		if err == nil {
			row["state"], row["pid"], row["checkpoint"], row["wait_hint_ms"] = status.State, status.ProcessId, status.CheckPoint, status.WaitHint
		}
		cfg, err := s.Config()
		row["config_status"] = environmentReadError(err)
		if err == nil {
			row["start_type"], row["service_type"], row["error_control"], row["delayed_auto_start"] = cfg.StartType, cfg.ServiceType, cfg.ErrorControl, cfg.DelayedAutoStart
		}
		s.Close()
		r[name] = row
	}
	return r
}

func connectionEnvironmentProcesses(ctx context.Context) any {
	pids := map[uint32]bool{uint32(os.Getpid()): true}
	environmentObservedPIDs.Lock()
	for pid := range environmentObservedPIDs.values {
		pids[pid] = true
	}
	pidOmissions := environmentObservedPIDs.omitted
	environmentObservedPIDs.Unlock()
	for _, e := range localWPDTrace.snapshot().FirstDecoded {
		if e.PID != 0 {
			pids[e.PID] = true
		}
	}
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return map[string]any{"query_status": environmentReadError(err)}
	}
	defer windows.CloseHandle(h)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var rows []any
	omitted := 0
	seen := make(map[uint32]bool)
	for err = windows.Process32First(h, &entry); err == nil; err = windows.Process32Next(h, &entry) {
		name := windows.UTF16ToString(entry.ExeFile[:])
		category := environmentProcessCategory(name)
		if !pids[entry.ProcessID] && category == "other" {
			continue
		}
		if len(rows) >= 64 || ctx.Err() != nil {
			omitted++
			continue
		}
		rows = append(rows, environmentProcessIdentity(entry.ProcessID, entry.ParentProcessID, category))
		seen[entry.ProcessID] = true
	}
	missing := 0
	for pid := range pids {
		if !seen[pid] {
			missing++
		}
	}
	status := "read_ok"
	if err != windows.ERROR_NO_MORE_FILES {
		status = environmentReadError(err)
	}
	return map[string]any{"query_status": status, "scope": "fixed_apple_wpd_names_and_observed_wpd_pids", "name_is_not_initiator_or_signature_proof": true, "entries": rows, "omitted": omitted, "observed_pid_capacity_omissions": pidOmissions, "observed_pids_not_resolved": missing, "enumeration_finished": err == windows.ERROR_NO_MORE_FILES}
}

func connectionEnvironmentUptime() any {
	p := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")
	if err := p.Find(); err != nil {
		return map[string]any{"query_status": environmentReadError(err)}
	}
	v, _, _ := p.Call()
	return map[string]any{"query_status": "read_ok", "milliseconds": uint64(v)}
}

func environmentProcessCategory(name string) string {
	switch strings.ToLower(name) {
	case "applemobiledeviceservice.exe":
		return "apple_mobile_service"
	case "appledevices.exe", "itunes.exe", "ituneshelper.exe", "itunesmobiledevicehelper.exe", "applemobiledevicehelper.exe":
		return "apple_device_client"
	case "wudfhost.exe":
		return "user_mode_driver_host"
	case "mdnsresponder.exe":
		return "bonjour"
	default:
		return "other"
	}
}

func environmentProcessIdentity(pid, parent uint32, category string) any {
	r := map[string]any{"pid": pid, "parent_pid": parent, "category_from_name": category, "signature_verified": false}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		r["query_status"] = environmentReadError(err)
		return r
	}
	defer windows.CloseHandle(h)
	var created, exit, kernel, user windows.Filetime
	err = windows.GetProcessTimes(h, &created, &exit, &kernel, &user)
	r["time_status"] = environmentReadError(err)
	if err == nil {
		r["creation_filetime_100ns"] = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
		r["kernel_100ns"] = uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
		r["user_100ns"] = uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	}
	var path [32768]uint16
	n := uint32(len(path))
	err = windows.QueryFullProcessImageName(h, 0, &path[0], &n)
	r["image_status"] = environmentReadError(err)
	if err == nil && n > 0 && n < uint32(len(path)) {
		image := windows.UTF16ToString(path[:n])
		sum := sha256.Sum256([]byte(strings.ToLower(image)))
		r["image_path_sha256"] = hex.EncodeToString(sum[:])
		if known := environmentProcessCategory(filepath.Base(image)); known != "other" {
			r["queried_image_category"] = known
		}
	}
	return r
}

func connectionEnvironmentSystemLoad() any {
	r := map[string]any{}
	var idle, kernel, user windows.Filetime
	ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemTimes").Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	r["cpu_status"] = "read_ok"
	if ok == 0 {
		r["cpu_status"] = environmentReadError(err)
	} else {
		r["idle_100ns"], r["kernel_including_idle_100ns"], r["user_100ns"] = uint64(idle.HighDateTime)<<32|uint64(idle.LowDateTime), uint64(kernel.HighDateTime)<<32|uint64(kernel.LowDateTime), uint64(user.HighDateTime)<<32|uint64(user.LowDateTime)
	}
	var memory struct {
		Length, Load                                                                                                                 uint32
		TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtendedVirtual uint64
	}
	memory.Length = uint32(unsafe.Sizeof(memory))
	ok, _, err = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&memory)))
	r["memory_status"] = "read_ok"
	if ok == 0 {
		r["memory_status"] = environmentReadError(err)
	} else {
		r["memory_load_percent"], r["physical_total_bytes"], r["physical_available_bytes"], r["pagefile_total_bytes"], r["pagefile_available_bytes"] = memory.Load, memory.TotalPhysical, memory.AvailablePhysical, memory.TotalPageFile, memory.AvailablePageFile
	}
	return r
}

func connectionEnvironmentPower() any {
	var p struct {
		AC, BatteryFlags, BatteryPercent, Saver uint8
		LifeSeconds, FullLifeSeconds            uint32
	}
	r := map[string]any{}
	ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemPowerStatus").Call(uintptr(unsafe.Pointer(&p)))
	r["query_status"] = "read_ok"
	if ok == 0 {
		r["query_status"] = environmentReadError(err)
	} else {
		r["ac_line_status"], r["battery_flags"], r["battery_percent"], r["battery_saver"] = p.AC, p.BatteryFlags, p.BatteryPercent, p.Saver
		r["unknown_sentinel_255_retained"] = true
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\USB`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		value, _, e := k.GetIntegerValue("DisableSelectiveSuspend")
		r["selective_suspend_override_status"] = environmentReadError(e)
		if e == nil {
			r["disable_selective_suspend_override"] = value
		}
	} else {
		r["selective_suspend_override_status"] = environmentReadError(err)
	}
	return r
}
