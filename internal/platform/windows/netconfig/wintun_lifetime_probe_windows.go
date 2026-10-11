//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
	"time"
	"unsafe"
)

// RunWintunModuleLifetimeSelfTest is a fixed five-round no-network experiment.
// It must run in a separately authenticated short-lived installed helper: the
// parent binds its real PID/creation/source and joins it, including a cancelled
// synchronous Create. No runtime argument selects a GUID, alias or command.
// Any unknown creation/mapping/close result stops the entire run. Existing
// devices are never opened, adopted, removed or "repaired" by this API.
func RunWintunModuleLifetimeSelfTest(ctx context.Context, dll string, hold bool, verifyInstalledOwner func() error) (report WintunLifetimeProbeReport, err error) {
	report = WintunLifetimeProbeReport{Schema: 1, ObservationOnly: true, HoldModule: hold, ProcessID: windows.GetCurrentProcessId(), Stage: "preflight", Rounds: []WintunLifetimeProbeRound{}}
	fail := func(code string) (WintunLifetimeProbeReport, error) {
		report.Code = code
		report.PinnedModules = wintun.ModuleLifetimeSnapshot().PinnedModules
		return report, errors.New(code)
	}
	if ctx == nil || verifyInstalledOwner == nil {
		return fail("WINTUN_PROBE_OWNER_REQUIRED")
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user) != nil {
		return fail("WINTUN_PROBE_PROCESS_UNPROVEN")
	}
	report.ProcessCreation = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	// This helper is never a process-wide production comparison. In particular
	// an irreversible prior PIN cannot masquerade as the OFF baseline.
	if report.ProcessCreation == 0 || wintun.ModuleLifetimeHoldEnabled() || wintun.ModuleLifetimeSnapshot().PinnedModules != 0 {
		return fail("WINTUN_PROBE_FRESH_PROCESS_REQUIRED")
	}
	owner := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return verifyInstalledOwner()
	}
	if owner() != nil {
		return fail("WINTUN_PROBE_OWNER_CHANGED")
	}
	if windows.RtlGetVersion().MajorVersion < 10 {
		return fail("WINTUN_PROBE_SUPPORTED_PLATFORM_REQUIRED")
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if e != nil {
		return fail("WINTUN_PROBE_LEASE_UNPROVEN")
	}
	h, e := windows.CreateMutex(&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, false, windows.StringToUTF16Ptr(`Global\USBLinkWintunLifecycleProbe`))
	if e != nil {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return fail("WINTUN_PROBE_ALREADY_RUNNING_OR_UNAVAILABLE")
	}
	defer windows.CloseHandle(h)
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return fail("WINTUN_PROBE_TOPOLOGY_LEASE_UNPROVEN")
	}
	defer release()
	pin, e := PinVerifiedWintunNative(dll, nil)
	if e != nil {
		return fail("WINTUN_PROBE_OFFICIAL_DLL_UNPROVEN")
	}
	defer pin.Close()
	for round := 1; round <= 5; round++ {
		sample := WintunLifetimeProbeRound{Round: round}
		report.Stage = "before_create"
		if owner() != nil {
			return fail("WINTUN_PROBE_OWNER_CHANGED")
		}
		before, _, e := readLifecycleProbeNative("", 0, 0)
		sample.Before = before
		if e != nil || !before.absent() {
			report.Rounds = append(report.Rounds, sample)
			return fail("WINTUN_PROBE_PREEXISTING_OR_UNREADABLE")
		}
		pre := func() error {
			if owner() != nil {
				return errors.New("WINTUN_PROBE_OWNER_CHANGED")
			}
			fresh, _, e := readLifecycleProbeNative("", 0, 0)
			if e != nil || !fresh.absent() {
				return errors.New("WINTUN_PROBE_PREEXISTING_OR_UNREADABLE")
			}
			// Official Create/Close queue an enumerator-wide orphan worker. This
			// experiment must not use that worker to clean an existing unknown
			// unhealthy Wintun node; reject it before any native adapter call.
			if verifyLifecycleProbeOtherNodes() != nil {
				return errors.New("WINTUN_PROBE_OTHER_NODE_UNHEALTHY_OR_UNKNOWN")
			}
			return owner()
		}
		observation := wintun.OwnedCreateObservation{}
		report.Stage = "creating"
		d, e := wintun.CreateLifecycleProbe(dll, hold, pre, &observation)
		sample.CreateCalled, sample.CreateReturned = observation.Called, observation.Returned
		if e != nil {
			sample.Code = "WINTUN_PROBE_CREATE_UNCONFIRMED"
			report.Rounds = append(report.Rounds, sample)
			return fail(sample.Code)
		}
		// The private returned creator is the only handle ever closed here.
		creator := func() bool {
			return d.FactoryHandleHeld() && d.GUID.String() == wintun.LifecycleProbeGUID && d.LUID != 0 && d.Index != 0 && observation.FixedGUIDVerified && observation.Called && observation.Returned && observation.Succeeded
		}
		report.Stage = "created_mapping"
		live, instance, readErr := readLifecycleProbeNative("", d.Index, d.LUID)
		if !creator() || owner() != nil || readErr != nil || !live.Complete || live.MIBMatches != 1 || live.InstalledMatches != 1 || live.ExactInstanceMatches != 1 || live.IPv4Matches != 0 || !live.TypedPresent || instance == "" {
			d.Close()
			sample.CloseReturned = true
			sample.Code = "WINTUN_PROBE_CREATED_OWNER_UNPROVEN"
			report.Rounds = append(report.Rounds, sample)
			return fail(sample.Code)
		}
		fresh, currentInstance, e := readLifecycleProbeNative(instance, d.Index, d.LUID)
		if e != nil || fresh != live || instance != currentInstance || !creator() || owner() != nil {
			d.Close()
			sample.CloseReturned = true
			sample.Code = "WINTUN_PROBE_CREATED_OWNER_CHANGED"
			report.Rounds = append(report.Rounds, sample)
			return fail(sample.Code)
		}
		sample.CreatorVerified = true
		index, luid := d.Index, d.LUID
		report.Stage = "closing"
		started := time.Now()
		d.Close()
		sample.CloseReturned = true
		// Close's void return is not absence. The fixture may reveal precisely a
		// MIB-only ghost, installed phantom, or still-present device separately.
		deadline := time.Now().Add(10 * time.Second)
		for {
			sample.After, _, e = readLifecycleProbeNative(instance, index, luid)
			if e != nil || owner() != nil {
				sample.Code = "WINTUN_PROBE_CLOSE_OBSERVATION_UNPROVEN"
				break
			}
			if sample.After.absent() {
				second, _, e2 := readLifecycleProbeNative(instance, index, luid)
				if e2 == nil && second.absent() && owner() == nil {
					sample.After = second
					break
				}
				sample.Code = "WINTUN_PROBE_CLOSE_OBSERVATION_CHANGED"
				break
			}
			if time.Now().After(deadline) {
				sample.Code = "WINTUN_PROBE_CLOSE_ABSENCE_UNCONFIRMED"
				break
			}
			select {
			case <-ctx.Done():
				sample.Code = "WINTUN_PROBE_CANCELLED_AFTER_CLOSE"
			case <-time.After(100 * time.Millisecond):
			}
			if sample.Code != "" {
				break
			}
		}
		sample.CloseSettleMS = uint32(time.Since(started).Milliseconds())
		report.Rounds = append(report.Rounds, sample)
		if sample.Code != "" {
			return fail(sample.Code)
		}
	}
	report.PinnedModules = wintun.ModuleLifetimeSnapshot().PinnedModules
	if owner() != nil {
		return fail("WINTUN_PROBE_OWNER_CHANGED")
	}
	report.Stage = "complete"
	return report, nil
}

func verifyLifecycleProbeOtherNodes() error {
	class, _ := windows.GUIDFromString(hostNetClass)
	// ROOT is included conservatively: the official Create may perform legacy
	// driver maintenance as well as the SWD enumerator's queued orphan cleanup.
	for _, enumerator := range []string{`SWD\Wintun`, `ROOT\Wintun`} {
		set, err := windows.SetupDiGetClassDevsEx(&class, enumerator, 0, 0, 0, "")
		if err != nil {
			return errors.New("WINTUN_PROBE_OTHER_ENUMERATOR_UNREADABLE")
		}
		complete := false
		for i := 0; i < 4096; i++ {
			info, err := set.EnumDeviceInfo(i)
			if err == windows.ERROR_NO_MORE_ITEMS {
				complete = true
				break
			}
			if err != nil {
				set.Close()
				return errors.New("WINTUN_PROBE_OTHER_ENUMERATOR_UNREADABLE")
			}
			var status, problem uint32
			if windows.CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0) != nil || problem != 0 || status&windows.DN_HAS_PROBLEM != 0 {
				set.Close()
				return errors.New("WINTUN_PROBE_OTHER_NODE_UNHEALTHY_OR_UNKNOWN")
			}
		}
		set.Close()
		if !complete {
			return errors.New("WINTUN_PROBE_OTHER_ENUMERATOR_LIMIT")
		}
	}
	return nil
}

// Complete installed (not PRESENT-only) enumeration and ALLCLASSES identity
// reads never suppress an unknown value or class-changed exact probe instance.
func readLifecycleProbeNative(expectedInstance string, expectedIndex uint32, expectedLUID uint64) (out WintunLifetimeProbeRead, instance string, err error) {
	var table *windows.MibIfTable2
	if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table) != nil || table == nil {
		return out, "", errors.New("WINTUN_PROBE_MIB_UNREADABLE")
	}
	if table.NumEntries > 65536 {
		windows.FreeMibTable(unsafe.Pointer(table))
		return out, "", errors.New("WINTUN_PROBE_MIB_LIMIT")
	}
	index, luid := expectedIndex, expectedLUID
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if strings.EqualFold(r.InterfaceGuid.String(), wintun.LifecycleProbeGUID) || windows.UTF16ToString(r.Alias[:]) == wintun.LifecycleProbeName {
			out.MIBMatches++
			if !strings.EqualFold(r.InterfaceGuid.String(), wintun.LifecycleProbeGUID) || windows.UTF16ToString(r.Alias[:]) != wintun.LifecycleProbeName || r.Type != 53 || r.InterfaceLuid == 0 || r.InterfaceIndex == 0 || (expectedLUID != 0 && (r.InterfaceLuid != expectedLUID || r.InterfaceIndex != expectedIndex)) {
				windows.FreeMibTable(unsafe.Pointer(table))
				return out, "", errors.New("WINTUN_PROBE_MIB_FOREIGN")
			}
			index, luid = r.InterfaceIndex, r.InterfaceLuid
		}
	}
	windows.FreeMibTable(unsafe.Pointer(table))
	var ip *windows.MibUnicastIpAddressTable
	if windows.GetUnicastIpAddressTable(windows.AF_INET, &ip) != nil || ip == nil {
		return out, "", errors.New("WINTUN_PROBE_ADDRESS_UNREADABLE")
	}
	if ip.NumEntries > 65536 {
		windows.FreeMibTable(unsafe.Pointer(ip))
		return out, "", errors.New("WINTUN_PROBE_ADDRESS_LIMIT")
	}
	for _, r := range unsafe.Slice(&ip.Table[0], int(ip.NumEntries)) {
		if (luid != 0 && r.InterfaceLuid == luid) || (index != 0 && r.InterfaceIndex == index) {
			out.IPv4Matches++
		}
	}
	windows.FreeMibTable(unsafe.Pointer(ip))
	class, _ := windows.GUIDFromString(hostNetClass)
	set, e := windows.SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")
	if e != nil {
		return out, "", errors.New("WINTUN_PROBE_INSTALLED_UNREADABLE")
	}
	defer set.Close()
	complete := false
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			complete = true
			break
		}
		if e != nil {
			return out, "", errors.New("WINTUN_PROBE_INSTALLED_UNREADABLE")
		}
		key, e := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if e == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if e != nil {
			return out, "", errors.New("WINTUN_PROBE_BINDING_UNREADABLE")
		}
		guid, has, e := nativeHostRegistryGUID(key)
		windows.RegCloseKey(key)
		if e != nil {
			return out, "", e
		}
		if !has || !strings.EqualFold(guid, wintun.LifecycleProbeGUID) {
			continue
		}
		out.InstalledMatches++
		if out.InstalledMatches > 1 {
			return out, "", errors.New("WINTUN_PROBE_BINDING_NOT_UNIQUE")
		}
		n, e := readNativeWintunNodeMetadata(set, info, guid)
		if e != nil {
			return out, "", e
		}
		instance = n.Instance
		if expectedInstance != "" && instance != expectedInstance {
			return out, "", errors.New("WINTUN_PROBE_INSTANCE_CHANGED")
		}
		var state, problem uint32
		stateErr := windows.CM_Get_DevNode_Status(&state, &problem, info.DevInst, 0)
		out.TypedPresent = validLifecycleProbeNode(n) && stateErr == nil && problem == 0 && state&windows.DN_HAS_PROBLEM == 0
	}
	if !complete {
		return out, "", errors.New("WINTUN_PROBE_INSTALLED_LIMIT")
	}
	all, e := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		return out, "", errors.New("WINTUN_PROBE_ALLCLASSES_UNREADABLE")
	}
	defer all.Close()
	complete = false
	needle := strings.ToUpper(wintun.LifecycleProbeGUID)
	for i := 0; i < 65536; i++ {
		info, e := all.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			complete = true
			break
		}
		if e != nil {
			return out, "", errors.New("WINTUN_PROBE_ALLCLASSES_UNREADABLE")
		}
		id, e := all.DeviceInstanceID(info)
		if e != nil {
			return out, "", errors.New("WINTUN_PROBE_INSTANCE_UNREADABLE")
		}
		if (expectedInstance != "" && strings.EqualFold(id, expectedInstance)) || strings.Contains(strings.ToUpper(id), needle) {
			out.ExactInstanceMatches++
		}
	}
	if !complete {
		return out, "", errors.New("WINTUN_PROBE_ALLCLASSES_LIMIT")
	}
	out.Complete = true
	return out, instance, nil
}
