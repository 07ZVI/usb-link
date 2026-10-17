//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const groupingSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

var groupingBytes = []byte{2, 0, 0}

// Local recovery contains the exact instance ID. It is admin-only and is never
// copied into the diagnostic report or uploaded. Only an originally absent
// EnumeratorClass is eligible, so restoring means deleting our own exact value.
type GroupingRecovery struct {
	ConfigurationPreserved bool   `json:"owned_configuration_preserved_for_product_on,omitempty"`
	Pending                bool   `json:"pending_transaction_found"`
	RegistryRestored       bool   `json:"registry_restored"`
	RestartAttempted       bool   `json:"target_restart_attempted"`
	RestartAccepted        bool   `json:"target_restart_accepted"`
	RebootRequired         bool   `json:"windows_restart_required"`
	RestartExitCode        *int   `json:"target_restart_exit_code,omitempty"`
	RootDevNodeStatus      string `json:"target_devnode_status,omitempty"`
	RootProblem            uint32 `json:"target_devnode_problem,omitempty"`
	AlreadyRestored        bool   `json:"original_loaded_layout_verified_without_restart,omitempty"`
	TargetDisconnected     bool   `json:"target_disconnected"`
	JournalCleared         bool   `json:"journal_cleared"`
	Error                  string `json:"error,omitempty"`
}
type GroupingResult struct {
	Application                  *ApplicationResult           `json:"application_trial,omitempty"`
	PeerProbe                    *PeerProbe                   `json:"scoped_peer_probe,omitempty"`
	Transaction                  grouptrial.Report            `json:"transaction"`
	Before                       Snapshot                     `json:"before"`
	Trial                        *StartupResult               `json:"trial_startup,omitempty"`
	ModeReactivation             *Result                      `json:"mode_reactivation,omitempty"`
	TrialRestart                 GroupingRecovery             `json:"trial_restart"`
	ReactivationWait             []grouptrial.ReadinessSample `json:"reactivation_wait,omitempty"`
	NetworkObservation           *NetworkObservation          `json:"passive_network_observation,omitempty"`
	AfterRestore                 Snapshot                     `json:"after_restore"`
	RestoreSamples               []StartupSample              `json:"restoration_samples,omitempty"`
	Recovery                     GroupingRecovery             `json:"restoration"`
	GroupingObserved             bool                         `json:"grouping_topology_observed"`
	NativeStartedNodes           int                          `json:"native_started_nodes"`
	LiveOriginalTopologyObserved bool                         `json:"live_original_topology_observed"`
	NetworkVerified              bool                         `json:"network_verified"`
	MoonlightVerified            bool                         `json:"moonlight_verified"`
}

// Fixed protected location makes interrupted transactions discoverable by the
// same single EXE. Refuse existing reparse points or unexpected ACLs; no ACLs
// are broadened or repaired. The share-zero file excludes concurrent launches.
func OpenGroupingRecoveryStore() (string, windows.Handle, string) {
	w, e := windows.GetWindowsDirectory()
	if e != nil {
		return "", 0, "WINDOWS_DIRECTORY_UNAVAILABLE"
	}
	dir := filepath.Join(w, "Temp", "Suhang-iPad-Grouping-Recovery")
	p, _ := windows.UTF16PtrFromString(dir)
	sd, e := windows.SecurityDescriptorFromString(groupingSDDL)
	if e != nil {
		return "", 0, "RECOVERY_ACL_UNAVAILABLE"
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if e = windows.CreateDirectory(p, &sa); e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return "", 0, "RECOVERY_DIRECTORY_UNAVAILABLE"
	}
	a, e := windows.GetFileAttributes(p)
	if e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || a&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return "", 0, "RECOVERY_DIRECTORY_UNSAFE"
	}
	actual, e := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil || !groupingACLMatches(actual, sd) {
		return "", 0, "RECOVERY_DIRECTORY_ACL_UNEXPECTED"
	}
	lp, _ := windows.UTF16PtrFromString(filepath.Join(dir, "launch.lock"))
	h, e := windows.CreateFile(lp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return "", 0, "ANOTHER_LAUNCH_OR_RECOVERY_LOCK_UNAVAILABLE"
	}
	return dir, h, ""
}

func groupingACLMatches(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
	control, _, e := actual.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	aces := func(sd *windows.SECURITY_DESCRIPTOR) ([]string, bool) {
		acl, _, e := sd.DACL()
		if e != nil || acl == nil || acl.AceCount != 2 {
			return nil, false
		}
		var out []string
		for i := uint32(0); i < 2; i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceSize < 8 || ace.Header.AceSize > 64 {
				return nil, false
			}
			out = append(out, string(unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize))))
		}
		sort.Strings(out)
		return out, true
	}
	a, ok := aces(actual)
	if !ok {
		return false
	}
	b, ok := aces(expected)
	return ok && a[0] == b[0] && a[1] == b[1]
}

func journalPath(dir string) string { return filepath.Join(dir, "pending.json") }

func recoveryKey(j groupingJournal) (registry.Key, string) {
	return groupingOwnedKey(j, registry.QUERY_VALUE|registry.SET_VALUE)
}

// Read-only startup proof uses the same ownership checks without requesting
// write access. Restoration retains its original read/write access.
func groupingOwnedKey(j groupingJournal, access uint32) (registry.Key, string) {
	if !validJournal(j) {
		return 0, "RECOVERY_RECORD_INVALID"
	}
	// Check the instance's current software-key association, even when unplugged,
	// to avoid restoring a key that Windows has reassigned to a different driver.
	ekey, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\`+j.RootID, registry.QUERY_VALUE)
	if e != nil {
		return 0, "RECOVERY_TARGET_KEY_UNAVAILABLE"
	}
	defer ekey.Close()
	d, _, e := ekey.GetStringValue("Driver")
	if e != nil || !strings.EqualFold(d, j.DriverKey) {
		return 0, "RECOVERY_DRIVER_ASSOCIATION_CHANGED"
	}
	filters, _, e := ekey.GetStringsValue("LowerFilters")
	found := false
	for _, f := range filters {
		if strings.EqualFold(f, "AppleLowerFilter") {
			found = true
		}
	}
	if e != nil || !found {
		return 0, "RECOVERY_APPLE_BINDING_CHANGED"
	}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\`+j.DriverKey, access)
	if e != nil {
		return 0, "RECOVERY_SOFTWARE_KEY_UNAVAILABLE"
	}
	v, _, e := k.GetStringValue("DriverVersion")
	if e != nil || v != "486.0.0.0" {
		k.Close()
		return 0, "RECOVERY_DRIVER_VERSION_CHANGED"
	}
	return k, ""
}

// Does not export native tool output or instance identifiers. The explicit
// instance argument restarts only this recorded root, never a class or bus.
func restartGroupingRoot(system string, j groupingJournal, r *GroupingRecovery) string {
	return restartGroupingRootChecked(system, j, r, false)
}

func restartGroupingRootChecked(system string, j groupingJournal, r *GroupingRecovery, alreadyAbsent bool) string {
	set, e := windows.SetupDiGetClassDevsEx(nil, "USB", 0, windows.DIGCF_PRESENT|windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		return "RESTART_TARGET_ENUMERATION_FAILED"
	}
	defer set.Close()
	present := false
	complete := false
	var rootInst uint32
	var rootService string
	var originalData []uint32
	var dataIDs []string
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			complete = true
			break
		}
		if e != nil {
			return "RESTART_TARGET_ENUMERATION_FAILED"
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			return "RESTART_TARGET_ID_UNAVAILABLE"
		}
		if strings.EqualFold(id, j.RootID) {
			present = true
			rootInst = uint32(info.DevInst)
			if v, er := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE); er == nil {
				rootService, _ = v.(string)
			}
			var status, problem uint32
			if windows.CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0) != nil {
				return "RESTART_TARGET_STATUS_UNAVAILABLE"
			}
			r.RootDevNodeStatus = fmt.Sprintf("0x%08x", status)
			r.RootProblem = problem
			if grouptrial.NeedsWindowsRestart(r.RootDevNodeStatus) {
				r.RebootRequired = true
				return "TARGET_WINDOWS_RESTART_REQUIRED"
			}
		}
		if alreadyAbsent && (strings.HasPrefix(strings.ToUpper(id), `USB\VID_05AC&PID_12AB&MI_03\`) || strings.HasPrefix(strings.ToUpper(id), `USB\VID_05AC&PID_12AB&MI_05\`)) {
			v, er := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE)
			service, _ := v.(string)
			var status, problem uint32
			// Original orphan data interfaces have no service and problem 28.
			if (er == nil || er == windows.ERROR_INVALID_DATA || er == windows.ERROR_FILE_NOT_FOUND) && service == "" && windows.CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0) == nil && problem == 28 {
				originalData = append(originalData, uint32(info.DevInst))
				dataIDs = append(dataIDs, strings.ToUpper(id))
			}
		}
	}
	if !complete {
		return "RESTART_TARGET_ENUMERATION_LIMIT"
	}
	if !present {
		r.TargetDisconnected = true
		return ""
	}
	if alreadyAbsent {
		data03, data05 := false, false
		for i, child := range originalData {
			var parent uint32
			rc, _, _ := windows.NewLazySystemDLL("cfgmgr32.dll").NewProc("CM_Get_Parent").Call(uintptr(unsafe.Pointer(&parent)), uintptr(child), 0)
			// PID/interface names alone are insufficient when another iPad exists.
			if rc == 0 && parent == rootInst {
				data03 = data03 || strings.Contains(dataIDs[i], "&MI_03\\")
				data05 = data05 || strings.Contains(dataIDs[i], "&MI_05\\")
			}
		}
		if grouptrial.OriginalGroupingRestored(true, rootService, r.RootProblem, r.RootDevNodeStatus, data03, data05) {
			r.AlreadyRestored = true
			return ""
		}
	}
	r.RestartAttempted = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, filepath.Join(system, "pnputil.exe"), "/restart-device", j.RootID)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if e = c.Run(); e != nil {
		if ctx.Err() != nil {
			return "TARGET_RESTART_TIMEOUT"
		}
		if exit, ok := e.(*exec.ExitError); ok {
			code := exit.ExitCode()
			r.RestartExitCode = &code
			if code == 3010 || code == 1641 {
				r.RebootRequired = true
				return "TARGET_WINDOWS_RESTART_REQUIRED"
			}
		}
		return "TARGET_RESTART_FAILED"
	}
	code := 0
	r.RestartExitCode = &code
	r.RestartAccepted = true
	return ""
}

func restoreGrouping(dir, system string, j groupingJournal) (r GroupingRecovery) {
	r.Pending = true
	k, err := recoveryKey(j)
	if err != "" {
		r.Error = err
		return
	}
	defer k.Close()
	b, _, e := k.GetBinaryValue("EnumeratorClass")
	alreadyAbsent := e == windows.ERROR_FILE_NOT_FOUND
	switch {
	case e == windows.ERROR_FILE_NOT_FOUND: // backup saved before Apply, or already restored
	case e != nil:
		r.Error = "RECOVERY_VALUE_UNREADABLE_OR_WRONG_TYPE"
		return
	case !bytes.Equal(b, groupingBytes):
		r.Error = "RECOVERY_VALUE_CHANGED_BY_OTHER_ACTION"
		return
	default:
		if e = k.DeleteValue("EnumeratorClass"); e != nil {
			r.Error = "RECOVERY_VALUE_DELETE_FAILED"
			return
		}
	}
	if _, _, e = k.GetBinaryValue("EnumeratorClass"); e != windows.ERROR_FILE_NOT_FOUND {
		r.Error = "RECOVERY_ABSENCE_NOT_CONFIRMED"
		return
	}
	r.RegistryRestored = true
	// Persist the deletion before removing the crash recovery record. Failure
	// keeps the journal for the next launch; this flush can block in Windows.
	v, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegFlushKey").Call(uintptr(k))
	if v != 0 {
		r.Error = "RECOVERY_REGISTRY_FLUSH_FAILED"
		return
	}
	r.Error = restartGroupingRootChecked(system, j, &r, alreadyAbsent)
	return
}

func RecoverGrouping(dir, system string) (r GroupingRecovery) {
	f, e := os.Open(journalPath(dir))
	if os.IsNotExist(e) {
		return
	}
	r.Pending = true
	if e != nil {
		r.Error = "RECOVERY_RECORD_UNAVAILABLE"
		return
	}
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	closeError := f.Close() // Close before Windows can remove pending.json.
	if e != nil || closeError != nil || len(b) > 8192 {
		r.Error = "RECOVERY_RECORD_INVALID"
		return
	}
	var j groupingJournal
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&j) != nil || !validJournal(j) {
		r.Error = "RECOVERY_RECORD_INVALID"
		return
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		r.Error = "RECOVERY_RECORD_INVALID"
		return
	}
	r = restoreGrouping(dir, system, j)
	if r.Error == "" {
		if e = os.Remove(journalPath(dir)); e != nil {
			r.Error = "RECOVERY_RECORD_REMOVE_FAILED"
		} else {
			r.JournalCleared = true
		}
	}
	return
}

type groupingBackend struct {
	version, dir, system    string
	mode                    Result
	result                  *GroupingResult
	j                       groupingJournal
	activate                func(Result) (Result, string)
	applicationConsent      func() bool
	applicationRestoreError string
	eventStartup            bool
	existingTarget          *existingNetworkTarget
}

func (b *groupingBackend) Eligible() (status string) {
	diagnostic := groupingEligibilityEvidence{Attempt: currentSoftwareAttempt()}
	defer func() { recordGroupingEligibility(diagnostic, status) }()
	s := Inspect()
	b.result.Before = s
	if !sameUSBTarget(b.mode.Before, s) || !HasActiveNCM(s) || len(s.Devices) != 1 || s.Devices[0].PID != "12AB" || s.Devices[0].CurrentConfiguration != 5 {
		return "TARGET_CHANGED_OR_NCM_NOT_ACTIVE"
	}
	if !modeResultIdentity(b.mode, true) {
		return "CURRENT_LAUNCH_IPAD_IDENTITY_REQUIRED"
	}
	qualified := false
	for _, c := range s.Devices[0].Configurations {
		if c.Value == s.Devices[0].CurrentConfiguration {
			qualified = groupingTrialConfig(c)
		}
	}
	if !qualified {
		return "DIAGNOSED_UNION_LAYOUT_REQUIRED"
	}
	var root *Node
	controls, data := 0, 0
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.IDPrefix == `USB\VID_05AC&PID_12AB` && strings.EqualFold(n.Service, "usbccgp") {
			root = n
		}
		if strings.EqualFold(n.Service, "UsbNcm") && n.Problem == 10 && n.StateError == "" {
			controls++
		}
		if (strings.HasSuffix(n.IDPrefix, "&MI_03") || strings.HasSuffix(n.IDPrefix, "&MI_05")) && n.Service == "" && n.Problem == 28 && n.StateError == "" {
			data++
		}
	}
	observed := groupingEligibilityInput{FailedControls: controls, UnboundData: data}
	if root != nil {
		observed.RootFound, observed.RootProblem = true, root.Problem
		observed.RootStateError, observed.DriverVersion = root.StateError, root.DriverVersion
		observed.EnumeratorError, observed.EnumeratorClass = root.EnumeratorError, root.EnumeratorClass
	}
	described := describeGroupingEligibility(observed)
	described.Attempt = diagnostic.Attempt
	diagnostic = described
	if root == nil || root.Problem != 0 || root.StateError != "" || root.DriverVersion != "486.0.0.0" || root.EnumeratorError != "WIN32_2" || controls != 2 || data != 2 {
		return "DIAGNOSED_UNGROUPED_NATIVE_FAILURE_REQUIRED"
	}
	if grouptrial.NeedsWindowsRestart(root.DevNodeStatus) {
		return "TARGET_WINDOWS_RESTART_REQUIRED"
	}
	// Mutations require the exact root instance from the current mode check too,
	// rather than accepting a replacement iPad of the same PID on the same port.
	sameRoot := false
	for _, n := range b.mode.Before.Nodes {
		if n.IDPrefix == `USB\VID_05AC&PID_12AB` && n.instanceID != "" && strings.EqualFold(n.instanceID, root.instanceID) {
			sameRoot = true
		}
	}
	if !sameRoot {
		return "ROOT_INSTANCE_CHANGED_SINCE_MODE_CHECK"
	}
	set, e := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_PRESENT|windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		return "SOFTWARE_KEY_IDENTITY_UNAVAILABLE"
	}
	defer set.Close()
	var driver string
	allDrivers := map[string]int{}
	complete := false
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			complete = true
			break
		}
		if e != nil {
			return "SOFTWARE_KEY_IDENTITY_UNAVAILABLE"
		}
		v, e := set.DeviceRegistryProperty(info, windows.SPDRP_DRIVER)
		if e != nil && e != windows.ERROR_INVALID_DATA && e != windows.ERROR_FILE_NOT_FOUND && e != windows.ERROR_NOT_FOUND {
			return "SOFTWARE_KEY_UNIQUENESS_QUERY_FAILED"
		}
		if e == nil {
			if d, ok := v.(string); ok {
				allDrivers[strings.ToUpper(d)]++
				id, er := set.DeviceInstanceID(info)
				if er != nil {
					return "SOFTWARE_KEY_IDENTITY_UNAVAILABLE"
				}
				if strings.EqualFold(id, root.instanceID) {
					driver = d
				}
			}
		}
	}
	if !complete || allDrivers[strings.ToUpper(driver)] != 1 {
		return "SOFTWARE_KEY_NOT_UNIQUE_OR_UNSUPPORTED"
	}
	j := groupingJournal{1, root.instanceID, driver, true}
	if !validJournal(j) {
		return "TARGET_ROOT_OR_SOFTWARE_KEY_UNSUPPORTED"
	}
	if b.j.RootID != "" && b.j != j {
		return "TARGET_CHANGED_DURING_CONSENT"
	}
	b.j = j
	k, err := recoveryKey(j)
	if err != "" {
		return err
	}
	defer k.Close()
	if _, _, e = k.GetBinaryValue("EnumeratorClass"); e != windows.ERROR_FILE_NOT_FOUND {
		return "ORIGINAL_GROUPING_VALUE_NOT_ABSENT"
	}
	return ""
}
func (b *groupingBackend) Save() string {
	data, e := json.Marshal(b.j)
	if e != nil {
		return "BACKUP_ENCODING_FAILED"
	}
	f, e := os.OpenFile(journalPath(b.dir), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "BACKUP_CREATE_FAILED"
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		os.Remove(journalPath(b.dir))
		return "BACKUP_WRITE_FAILED"
	}
	return ""
}
func (b *groupingBackend) Apply() string {
	done := RecordConnectionOperation("grouping_write")
	defer done()
	// Revalidate hardware and original state after the durable backup too.
	if e := b.Eligible(); e != "" {
		return e
	}
	k, err := recoveryKey(b.j)
	if err != "" {
		return err
	}
	defer k.Close()
	if e := k.SetBinaryValue("EnumeratorClass", groupingBytes); e != nil {
		return "GROUPING_VALUE_WRITE_FAILED"
	}
	v, _, e := k.GetBinaryValue("EnumeratorClass")
	if e != nil || !bytes.Equal(v, groupingBytes) {
		return "GROUPING_VALUE_READBACK_FAILED"
	}
	return ""
}
func (b *groupingBackend) Restart() string {
	done := RecordConnectionOperation("device_restart")
	defer done()
	var r GroupingRecovery
	e := restartGroupingRoot(b.system, b.j, &r)
	b.result.TrialRestart = r
	if e == "" && r.TargetDisconnected {
		return "TARGET_DISCONNECTED_BEFORE_TRIAL_RESTART"
	}
	return e
}

// USB parent restart may reset the device's active configuration. Revalidate
// the exact root and owned setting before one separately consented mode rearm.
func (b *groupingBackend) Activate() string {
	ctx, cancel := context.WithTimeout(connectionContext(), 20*time.Second)
	defer cancel()
	samples, waitError := grouptrial.WaitReactivation(ctx, 500*time.Millisecond, func(ctx context.Context) grouptrial.ReadinessEvidence {
		fresh := inventory(ctx)
		e := grouptrial.ReadinessEvidence{QueryFailed: fresh.Error != "", Devices: len(fresh.Devices)}
		if len(fresh.Devices) == 1 {
			e.PhysicalMatches = sameUSBTarget(b.mode.Before, fresh)
		}
		for _, n := range fresh.Nodes {
			if n.IDPrefix != `USB\VID_05AC&PID_12AB` {
				continue
			}
			e.Roots++
			e.RootMatches = strings.EqualFold(n.instanceID, b.j.RootID)
			e.RootStateReadable = n.StateError == "" && n.DevNodeStatus != ""
			e.RootProblemFree = n.Problem == 0
			e.NeedsReboot = grouptrial.NeedsWindowsRestart(n.DevNodeStatus)
		}
		// A failed hub scan cannot prove that an absent target is re-enumerating.
		e.QueryIncomplete = e.Devices == 0 && fresh.HubErrors > 0
		return e
	})
	b.result.ReactivationWait = samples
	if waitError != "" {
		return waitError
	}
	if ctx.Err() != nil {
		return "MODE_REACTIVATION_CANCELLED"
	}
	k, err := recoveryKey(b.j)
	if err != "" {
		return err
	}
	value, _, e := k.GetBinaryValue("EnumeratorClass")
	k.Close()
	if e != nil || !bytes.Equal(value, groupingBytes) {
		return "GROUPING_VALUE_CHANGED_BEFORE_MODE_REACTIVATION"
	}
	if b.activate == nil {
		return "MODE_REACTIVATION_CALLBACK_UNAVAILABLE"
	}
	mode, outcome := b.activate(b.mode)
	b.result.ModeReactivation = &mode
	if outcome != "" {
		return outcome
	}
	if !sameRootInstance(b.mode.Before, mode.Before) {
		return "ROOT_CHANGED_DURING_MODE_REACTIVATION"
	}
	after := mode.Before
	if mode.After != nil {
		after = *mode.After
	}
	if !sameRootInstance(b.mode.Before, after) || !HasActiveNCM(after) {
		return "MODE_REACTIVATION_NCM_UNCONFIRMED"
	}
	// Recheck ownership after the additional runtime consent dialog/request.
	k, err = recoveryKey(b.j)
	if err != "" {
		return err
	}
	value, _, e = k.GetBinaryValue("EnumeratorClass")
	k.Close()
	if e != nil || !bytes.Equal(value, groupingBytes) {
		return "GROUPING_VALUE_CHANGED_AFTER_MODE_REACTIVATION"
	}
	b.mode = mode
	return ""
}
func (b *groupingBackend) Observe() string {
	// Native restart is an accepted request, not proof of device readiness.
	var t StartupResult
	if b.eventStartup {
		t = runStartupCheck(b.version, &b.mode.Before, &b.mode, true, b.dir, "grouping_observe")
	} else {
		time.Sleep(2 * time.Second)
		t = RunStartupCheckAfterMode(b.version, b.mode)
	}
	b.result.Trial = &t
	s := t.Before
	if len(t.Samples) > 0 {
		s = t.Samples[len(t.Samples)-1].Snapshot
	}
	if sameUSBTarget(b.mode.Before, s) && HasActiveNCM(s) {
		controls, data := 0, 0
		for _, n := range s.Nodes {
			if strings.EqualFold(n.Service, "UsbNcm") {
				controls++
				if grouptrial.NativeStartObserved(n.Problem, n.StateError, n.DevNodeStatus) {
					b.result.NativeStartedNodes++
				}
			}
			if strings.HasSuffix(n.IDPrefix, "&MI_03") || strings.HasSuffix(n.IDPrefix, "&MI_05") {
				data++
			}
		}
		b.result.GroupingObserved = controls == 2 && data == 0
		if b.result.GroupingObserved {
			recordConnectionStage("grouping_applied", "exact_root_two_controls_no_data_nodes")
		}
	}
	if b.result.NativeStartedNodes > 0 {
		if SimplifiedIPadNetworkConfigured() {
			proof, reason := configuredStartupProof(connectionContext(), b.dir, b.mode, s, startupReadinessFromSnapshot(s))
			if !proof.ready() {
				b.applicationRestoreError = "PRODUCT_STARTUP_TOPOLOGY_UNPROVEN: " + reason
				return "PRODUCT_STARTUP_TOPOLOGY_UNPROVEN"
			}
		}
		recordConnectionStage("native_ncm_started", "same_target_native_started_node_observed")
		observed := b.observeNetwork()
		b.result.NetworkObservation = &observed
		peer := b.waitForPeerReady()
		b.result.PeerProbe = &peer
		app := b.runApplication(peer)
		b.result.Application = &app
	}
	return t.Status
}
func (b *groupingBackend) Restore() string {
	if SimplifiedIPadNetworkConfigured() {
		j, found, e := readOwnedPendingNetworkGrouping(b.dir)
		if e != nil {
			return "PRODUCT_PENDING_RETAINED_UNPROVEN: " + e.Error()
		}
		if found && j == b.j {
			return "OWNED_NETWORK_GROUPING_RETAINED"
		}
		return "PRODUCT_PENDING_RETAINED_IDENTITY_UNPROVEN"
	}

	done := RecordConnectionOperation("grouping_restore")
	defer done()
	b.result.Recovery = restoreGrouping(b.dir, b.system, b.j)
	if b.result.Recovery.Error != "" {
		return b.result.Recovery.Error
	}
	return b.applicationRestoreError
}
func (b *groupingBackend) Clear() string {
	if e := os.Remove(journalPath(b.dir)); e != nil {
		return "RECOVERY_RECORD_REMOVE_FAILED"
	}
	b.result.Recovery.JournalCleared = true
	return ""
}

func RunGroupingTrial(version, dir, system string, mode Result, consent func() bool, activate func(Result) (Result, string), applicationConsent func() bool) (r GroupingResult) {
	b := &groupingBackend{version: version, dir: dir, system: system, mode: mode, result: &r, activate: activate, applicationConsent: applicationConsent}
	r.Transaction = grouptrial.Run(b, consent)
	if r.Transaction.RestoreCompleted {
		start := time.Now()
		for _, seconds := range []int{0, 1, 3} {
			if wait := time.Until(start.Add(time.Duration(seconds) * time.Second)); wait > 0 {
				time.Sleep(wait)
			}
			r.RestoreSamples = append(r.RestoreSamples, StartupSample{ElapsedMS: time.Since(start).Milliseconds(), Snapshot: Inspect()})
		}
	}
	r.AfterRestore = Inspect()
	if r.Transaction.RestoreCompleted && sameUSBTarget(mode.Before, r.AfterRestore) && HasActiveNCM(r.AfterRestore) {
		rootOK := false
		data := 0
		for _, n := range r.AfterRestore.Nodes {
			if n.IDPrefix == `USB\VID_05AC&PID_12AB` && n.Problem == 0 && n.StateError == "" && n.EnumeratorError == "WIN32_2" {
				rootOK = true
			}
			if (strings.HasSuffix(n.IDPrefix, "&MI_03") || strings.HasSuffix(n.IDPrefix, "&MI_05")) && n.Problem == 28 && n.Service == "" {
				data++
			}
		}
		r.LiveOriginalTopologyObserved = rootOK && data == 2
	}
	return
}
