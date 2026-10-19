//go:build windows && amd64

package macconnection

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/usbhost"
	"suhang/usbnet/internal/dependencies"
	"suhang/usbnet/internal/diagnostics/exitrecord"
	"suhang/usbnet/internal/diagnostics/logfile"
	"suhang/usbnet/internal/diagnostics/probecontrol"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"suhang/usbnet/internal/diagnostics/throughput"
	"suhang/usbnet/internal/platform/windows/background"
	"suhang/usbnet/internal/platform/windows/installer"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/security/usbgateway"
	"suhang/usbnet/internal/sharing/usbhttp"
	"suhang/usbnet/internal/sharing/usbservice"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/ncm"
	"suhang/usbnet/internal/transport/parentlifetime"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
	"suhang/usbnet/internal/transport/winusb"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Assigned before sessions start. Contains status only, never connection credentials.
var DeveloperStatus func() any

// Assigned once before sessions start; provides bounded, memory-only evidence.
var ConnectionEvidence func() any

// CoreHealthEvidence returns small independent rows (core lifecycle, pipe
// failures) so a large unrelated row can never displace them.
var CoreHealthEvidence func() []any
var RuntimeNetworkEvidence func() any
var TrustEvidence func() any
var TimingEvidence func() any
var PhotoEvidence func() any
var WPDTraceEvidence func() any
var PhotoPolicyEvidence func() any
var NCMDirectEvidence func() any
var AMDSHoldEvidence func() any

// MacMTUCapSetting returns the developer MTU cap for the next Mac session:
// "auto", "9000" or "1500". Nil or an unknown value means auto.
var MacMTUCapSetting func() string
var ConnectionArchiveEvidence func() any
var NativeUSBEvidence func() any
var NativePnPEvidence func() any

func safeExisting(path string) bool {
	v, e := os.Lstat(path)
	if e != nil || v.Mode()&os.ModeSymlink != 0 || !v.Mode().IsRegular() {
		return false
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return false
	}
	a, e := windows.GetFileAttributes(p)
	return e == nil && a&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}
func record(dir string) (sessionRecord, error) {
	var r sessionRecord
	p := filepath.Join(dir, "owned-session.json")
	if !safeExisting(p) {
		return r, fmt.Errorf("owned record unavailable")
	}
	f, e := os.Open(p)
	if e != nil {
		return r, fmt.Errorf("owned record unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil || len(b) > 8192 {
		return r, fmt.Errorf("owned record invalid")
	}
	r, e = parseSessionRecord(b)
	if e == nil && r.Version == bridge.RetainedSessionVersion {
		return bridge.ReadRetainedOwnedSession(dir)
	}
	if e == nil && r.Version == bridge.ResidentSessionVersion {
		return bridge.ReadResidentOwnedSession(dir)
	}
	return r, e
}

// Recover only rules bearing the protected, generated ownership token. Never
// remove a broadly matched adapter or terminate an unrecognized running bridge.
func Recover(parent string) error {
	_, err := RecoverWithReport(parent)
	return err
}
func RecoverWithReport(parent string) (RecoveryReport, error) {
	return recoverWithDrain(parent, nil)
}
func recoverWithDrain(parent string, drain *uninstallRuntimeDrain) (RecoveryReport, error) {
	var report RecoveryReport
	names, err := recoveryRuntimeNames(parent)
	if err != nil {
		return report, err
	}
	for _, name := range names {
		var output recoveryOutput
		err := recoverDirectoryWithDrain(filepath.Join(parent, name), log.New(&output, "", 0), drain)
		entry := RecoveryEntry{Runtime: name, Output: output.String()}
		if err != nil {
			entry.Error = err.Error()
			report.Error = err.Error()
		}
		report.Entries = append(report.Entries, entry)
		if err != nil {
			return report, err
		}
	}
	return report, nil
}
func recoverDirectory(dir string) error {
	return recoverDirectoryLogged(dir, log.New(io.Discard, "", 0))
}
func recoverDirectoryLogged(dir string, l *log.Logger) error {
	return recoverDirectoryWithDrain(dir, l, nil)
}
func recoverDirectoryWithDrain(dir string, l *log.Logger, drain *uninstallRuntimeDrain) error {
	if _, e := os.Stat(filepath.Join(dir, "owned-session.json")); os.IsNotExist(e) {
		return nil
	}
	i, e := os.Lstat(dir)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("MAC_RUNTIME_OWNERSHIP_UNAVAILABLE")
	}
	r, e := record(dir)
	if e != nil {
		return fmt.Errorf("MAC_RECOVERY_RECORD_INVALID: %w", e)
	}
	if drain != nil {
		if e = drain.verify(filepath.Dir(dir)); e != nil {
			return e
		}
	} else {
		release, e := winusb.OwnRuntime()
		if e != nil {
			if errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
				return fmt.Errorf("MAC_BRIDGE_STILL_RUNNING: %w", e)
			}
			return fmt.Errorf("MAC_BRIDGE_LOCK_UNAVAILABLE: %w", e)
		}
		defer release()
	}
	// A persistent original is never allowed to fall through legacy FullRecovery
	// or broad adapter deletion, even when this process selected the feature OFF.
	if _, statErr := os.Lstat(filepath.Join(filepath.Dir(dir), "usb-interface-config.json")); statErr == nil {
		_, owned, proofErr := interfaceconfig.ReadPersistentOriginalSnapshot(filepath.Dir(dir), "mac")
		if proofErr != nil {
			return fmt.Errorf("MAC_PERSISTENT_RECOVERY_UNPROVEN: %w", proofErr)
		}
		if _, dadFound, dadError := interfaceconfig.ReadDADOriginalScope(filepath.Dir(dir), "mac"); dadError != nil {
			return fmt.Errorf("MAC_DAD_RECOVERY_ORIGINAL_UNPROVEN: %w", dadError)
		} else if dadFound && !owned {
			return fmt.Errorf("MAC_DAD_RECOVERY_WITHOUT_FACTORY_ORIGINAL_PENDING")
		}
		if owned {
			if r.Version != bridge.RetainedSessionVersion || r.Retained == nil {
				return fmt.Errorf("MAC_PERSISTENT_COMPLETED_SESSION_UNPROVEN")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			s := interfaceconfig.Scope{Role: "mac", GUID: r.GUID, Index: r.Retained.Index, LUID: r.Retained.LUID}
			if e := interfaceconfig.RecoverPersistentMacSession(ctx, filepath.Dir(dir), s, r.Retained.Created, r.Retained.Mode, r.Retained.ReceiptSHA256, func(p usbaddress.InterfaceProof, verify func() error) error {
				return netconfig.CleanupRetainedMacSessionNative(ctx, p, r.Token, verify, l)
			}); e != nil {
				return fmt.Errorf("MAC_PERSISTENT_SESSION_CLEANUP_UNPROVEN: %w", e)
			}
			return os.Remove(filepath.Join(dir, "owned-session.json"))
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("MAC_PERSISTENT_RECOVERY_STORE_UNREADABLE")
	}
	if r.Version == bridge.RetainedSessionVersion {
		// An explicit successful restore may consume its persistent obligation. Its
		// completed protected session still cannot authorize a present adapter.
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		if e := netconfig.RecoverMacSessionNative(ctx, r.GUID, r.Token, l); e != nil {
			return e
		}
		return os.Remove(filepath.Join(dir, "owned-session.json"))
	}
	if r.Version == bridge.ResidentSessionVersion {
		// Complete native absence consumes only this exact protected session;
		// independent resident rule receipts survive normal recovery.
		return bridge.ConsumeResidentOwnedSession(dir, r, func() error {
			absent, err := netconfig.MacAdapterAbsentNative()
			if err != nil {
				return fmt.Errorf("MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN: %w", err)
			}
			if !absent {
				return fmt.Errorf("MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN")
			}
			return nil
		})
	}
	if netconfig.NativeNetworkEnabled() {
		// The selected full native experiment retains its original fence below.
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		if e := netconfig.RecoverMacSessionNative(ctx, r.GUID, r.Token, l); e != nil {
			return fmt.Errorf("MAC_ADAPTER_RECOVERY_UNCONFIRMED: %w", e)
		}
		if e := os.Remove(filepath.Join(dir, "owned-session.json")); e != nil {
			return fmt.Errorf("MAC_RECOVERY_JOURNAL_NOT_CLEARED: %w", e)
		}
		return nil
	}

	// Complete legacy absence needs no PowerShell. Unknown queries, ghosts or
	// remaining exact token rules retain the original recovery obligation.
	absenceCtx, cancelAbsence := context.WithTimeout(context.Background(), 10*time.Second)
	absenceErr := netconfig.VerifyMacCleanupNative(absenceCtx, r.GUID, r.Token, l)
	cancelAbsence()
	if absenceErr == nil {
		return os.Remove(filepath.Join(dir, "owned-session.json"))
	}
	script, e := netconfig.FullRecovery(r.GUID, r.Token)
	if e != nil {
		return e
	}
	endRecoveryScript := shutdowntrace.Begin(shutdowntrace.PhaseMacRecoveryScript)
	e = netconfig.RunLegacyRoleContext(context.Background(), "mac_recovery", script, l)
	endRecoveryScript()
	if e != nil {
		return fmt.Errorf("MAC_ADAPTER_RECOVERY_UNCONFIRMED: %w", e)
	}

	if e = os.Remove(filepath.Join(dir, "owned-session.json")); e != nil {
		return fmt.Errorf("MAC_RECOVERY_JOURNAL_NOT_CLEARED: %w", e)
	}
	return nil
}

func currentPair() (string, map[int]winusb.Node, error) {
	nodes, e := winusb.Enumerate(log.New(io.Discard, "", 0))
	if e != nil {
		return "", nil, e
	}
	parents := map[string]bool{}
	pairs := map[int]winusb.Node{}
	for _, n := range nodes {
		mi, ok := installer.InterfaceNumber(n.ID)
		if !ok {
			continue
		}
		if n.Parent == "" {
			return "", nil, fmt.Errorf("missing parent")
		}
		parents[strings.ToUpper(n.Parent)] = true
		if mi < 2 {
			if _, ok := pairs[mi]; ok {
				return "", nil, fmt.Errorf("ambiguous interface")
			}
			pairs[mi] = n
		}
	}
	if len(parents) != 1 || len(pairs) != 2 {
		return "", nil, fmt.Errorf("one Mac and first pair required")
	}
	return pairs[0].Parent, pairs, nil
}
func CurrentRoot() string { return currentObservedRoot() }

// RetireLegacyForUpgrade stops/removes the verified legacy service before
// startup recovery. Unrecognized extra files remain as a diagnostic warning.
func RetireLegacyForUpgrade() (retired bool, warning string, err error) {
	m, e := mgr.Connect()
	if e != nil {
		return false, "", e
	}
	defer m.Disconnect()
	s, e := m.OpenService(background.ServiceName)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return false, "", nil
	}
	if e != nil {
		return false, "", e
	}
	s.Close()
	if e = background.Uninstall(); e != nil {
		remaining, check := m.OpenService(background.ServiceName)
		if check == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return true, e.Error(), nil
		}
		if check == nil {
			remaining.Close()
		}
		return false, "", e
	}
	return true, "", nil
}

func Run(ctx context.Context, parent string, payload, manifest []byte, consent func(string) bool, notify func(Result)) Result {
	return RunArchive(ctx, parent, ArchiveBytes(payload), manifest, consent, notify)
}
func RunArchive(ctx context.Context, parent string, payload RuntimeArchive, manifest []byte, consent func(string) bool, notify func(Result)) (out Result) {
	return RunArchiveWithHostJoin(ctx, parent, payload, manifest, consent, notify, nil)
}

// Device binding and USB initialization may precede the host generation.
// No gateway admission or network mutation occurs until the real host joins.
func RunArchiveWithHostJoin(ctx context.Context, parent string, payload RuntimeArchive, manifest []byte, consent func(string) bool, notify func(Result), joinHost func() error) (out Result) {
	out.Stage = "MAC_PREPARING"
	nativeAttempt := beginNativeFailureAttempt()
	root, pairs, e := currentPair()
	if e != nil {
		out.Error = "MAC_EXACT_PAIR_UNAVAILABLE"
		return
	}
	if !consent(root) || ctx.Err() != nil || CurrentRoot() != root {
		out.Error = "MAC_CONNECTION_DECLINED_OR_CHANGED"
		return
	}
	if out.LegacyServiceMigrated, _, e = RetireLegacyForUpgrade(); e != nil {
		out.Error = "OWNED_LEGACY_MAC_SERVICE_MIGRATION_FAILED"
		return
	}
	if e = Recover(parent); e != nil {
		out.Error = e.Error()
		return
	}
	dir, e := unpackArchive(parent, payload, manifest)
	if e != nil {
		out.Error = "MAC_EMBEDDED_RUNTIME_PREPARATION_FAILED"
		out.PreparationError = e.Error()
		return
	}
	f, e := logfile.Open(filepath.Join(dir, "installer.log"), 1024*1024)
	if e != nil {
		out.Error = "MAC_LOG_UNAVAILABLE"
		return
	}
	defer f.Close()
	l := log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	for n := 0; n < 2; n++ {
		if CurrentRoot() != root || ctx.Err() != nil {
			out.Error = "MAC_TARGET_CHANGED_BEFORE_BINDING"
			return
		}
		if strings.EqualFold(pairs[n].Service, "WinUSB") {
			continue
		}
		zadig, e := dependencies.Ensure(ctx, "zadig")
		if e != nil {
			out.Error = e.Error()
			return
		}
		if installer.VerifySignature(zadig, l) != nil {
			out.Error = "MAC_SIGNED_BINDING_TOOL_UNVERIFIED"
			return
		}
		driverDir, e := os.MkdirTemp(dir, fmt.Sprintf("driver-mi%02x-", n))
		if e != nil {
			out.Error = "MAC_DRIVER_STAGE_FAILED"
			return
		}
		ini, e := installer.ZadigConfig(driverDir)
		if e != nil || os.WriteFile(filepath.Join(dir, "zadig.ini"), []byte(ini), 0600) != nil {
			out.Error = "MAC_BINDING_PLAN_FAILED"
			return
		}
		if installer.ExtractOne(ctx, zadig, driverDir, n, root, l) != nil || installer.BindGenerated(driverDir, n, root, l) != nil {
			out.Error = "MAC_WINUSB_BINDING_FAILED"
			return
		}
	}
	verified := false
	deadline := time.Now().Add(30 * time.Second)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		current, p, e := currentPair()
		if e == nil && current == root && strings.EqualFold(p[0].Service, "WinUSB") && strings.EqualFold(p[1].Service, "WinUSB") && p[0].Problem == 0 && p[1].Problem == 0 && len(p[0].Paths) > 0 && len(p[1].Paths) > 0 {
			verified = true
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(300 * time.Millisecond):
		}
	}
	if !verified {
		out.Error = "MAC_WINUSB_PAIR_NOT_READY"
		return
	}
	// Persistent factory operations hold the topology lease before the child
	// announces gateway attachment. Join the host first: its preparation needs
	// the same lease. The later attachment callback still rechecks the joined
	// generation before admitting traffic.
	if interfaceconfig.PersistentEnabled() && joinHost != nil {
		if e = joinHost(); e != nil {
			out.Error = "MAC_SHARED_HOST_JOIN_FAILED: " + e.Error()
			return
		}
	}
	var token [12]byte
	if _, e = rand.Read(token[:]); e != nil {
		out.Error = "MAC_STOP_TOKEN_UNAVAILABLE"
		return
	}
	name := `Local\SuhangUSBBridgeStop-` + hex.EncodeToString(token[:])
	event, e := windows.CreateEvent(nil, 1, 0, windows.StringToUTF16Ptr(name))
	if e != nil {
		out.Error = "MAC_STOP_EVENT_UNAVAILABLE"
		return
	}
	defer windows.CloseHandle(event)
	gateName := `Local\USBLinkGatewayReady-` + hex.EncodeToString(token[:])
	gateDescriptor, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if e != nil {
		out.Error = "MAC_GATEWAY_EVENT_ACL_FAILED"
		return
	}
	gateAttributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: gateDescriptor}
	gateEvent, e := windows.CreateEvent(&gateAttributes, 1, 0, windows.StringToUTF16Ptr(gateName))
	if e != nil {
		out.Error = "MAC_GATEWAY_EVENT_UNAVAILABLE"
		return
	}
	defer windows.CloseHandle(gateEvent)
	securityDir, e := connectioninstall.SecurityDirectory()
	if e != nil {
		out.Error = "MAC_GATEWAY_STORE_UNAVAILABLE"
		return
	}
	gate, e := usbgateway.New(securityDir)
	if e != nil {
		out.Error = "MAC_GATEWAY_PREPARATION_FAILED: " + e.Error()
		return
	}
	parentExe, e := os.Executable()
	if e != nil {
		out.Error = "MAC_GATEWAY_APPLICATION_UNAVAILABLE"
		return
	}
	bridgeExe := filepath.Join(dir, "suhang-usbnet.exe")
	var gateStop func() error
	defer func() {
		if gateStop != nil && out.CleanupConfirmed {
			if e := gateStop(); e != nil {
				out.CleanupConfirmed = false
				out.Error = "MAC_GATEWAY_CLEANUP_FAILED: " + e.Error()
			}
		}
	}()
	parentLink, e := parentlifetime.Prepare()
	if e != nil {
		out.Error = "MAC_PARENT_LINK_UNAVAILABLE"
		return
	}
	defer parentLink.Close()
	cmd := exec.Command(bridgeExe, "--parent-handle", strconv.FormatUint(uint64(parentLink.Handle), 10), "--parent-pid", strconv.FormatUint(uint64(parentLink.PID), 10), "--parent-creation", strconv.FormatUint(parentLink.Creation, 10), "--gateway-ready-event", gateName, "--stop-event", name, "--address-profile", "unified", "--shared-host="+strconv.FormatBool(joinHost != nil || SharedWindowsHostReady()), "--native-network="+strconv.FormatBool(netconfig.NativeNetworkEnabled()), "--dad-zero="+strconv.FormatBool(interfaceconfig.DADZeroEnabled()), "--persistent-config="+strconv.FormatBool(interfaceconfig.PersistentEnabled()))
	if netconfig.ResidentFirewallEnabled() || wintun.ModuleLifetimeHoldEnabled() {
		binding, verifyErr := connectioninstall.CurrentCoreBinding()
		if verifyErr != nil || binding.Executable != parentExe || connectioninstall.VerifyCoreExecutable(parentExe) != nil || connectioninstall.VerifyCoreServiceProcess(parentLink.PID) != nil {
			out.Error = "MAC_RESIDENT_CORE_BINDING_UNPROVEN"
			return
		}
		cmd.Args = append(cmd.Args, "--core-exe", parentExe)
		if netconfig.ResidentFirewallEnabled() {
			cmd.Args = append(cmd.Args, "--resident-firewall=true")
		}
	}
	cmd.Args = append(cmd.Args, "--internet-root", root)
	mtuCap := ncm.MTUCapAuto
	if MacMTUCapSetting != nil {
		if c, err := ncm.ParseMTUCap(MacMTUCapSetting()); err == nil {
			mtuCap = c
		}
	}
	out.MTUCap = mtuCap.String()
	cmd.Args = append(cmd.Args, "--mac-mtu-cap="+mtuCap.String())
	cmd.Args = append(cmd.Args, "--wintun-module-hold="+strconv.FormatBool(wintun.ModuleLifetimeHoldEnabled()))
	cmd.Args = append(cmd.Args, "--owned-dad-zero="+strconv.FormatBool(interfaceconfig.OwnedDADZeroEnabled()))
	cmd.Args = append(cmd.Args, "--combined-legacy-network="+strconv.FormatBool(netconfig.CombinedLegacyNetworkEnabled()))
	dll, e := dependencies.Ensure(ctx, "wintun")
	if e != nil {
		out.Error = e.Error()
		return
	}
	cmd.Args = append(cmd.Args, "--wintun-path", dll)
	cmd.Dir = dir
	// A detached console process keeps the explicit stdout/stderr pipes but
	// never creates or inherits a console host; shutdown uses the owned stop event.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008, AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(parentLink.Handle)}}
	pipeR, pipeW := io.Pipe()
	cmd.Stdout = io.MultiWriter(l.Writer(), pipeW)
	cmd.Stderr = cmd.Stdout
	var mu sync.Mutex
	var stopServices func()
	var firewallShadowOnce macFirewallShadowOnce
	var speedTest *throughput.Server
	defer func() {
		if speedTest != nil {
			throughput.SetDeviceCurrent("Mac", nil)
			speedTest.Close()
		}
	}()
	start := time.Now()
	previousTime := start
	var previousIn, previousOut uint64
	update := func(fn func(*Result)) {
		mu.Lock()
		fn(&out)
		value := out
		mu.Unlock()
		if notify != nil {
			notify(value)
		}
	}
	readerDone := make(chan struct{})
	childBound := make(chan struct{})
	var nativeBinding nativeChildBinding
	var nativeBindingValid bool
	go func() {
		defer close(readerDone)
		scanner := bufio.NewScanner(pipeR)
		scanner.Buffer(make([]byte, 4096), 65536)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, netconfig.NativeFailurePrefix) && len(line) <= 1024 {
				<-childBound
				if nativeBindingValid {
					if failure, e := parseNativeFailureLine(line); e == nil && recordNativeFailure(nativeAttempt, nativeBinding, failure) {
						update(func(r *Result) { r.NativeStartupFailure = failure; r.NativeDiagnosticSource = "mac_child" })
					}
				}
			}
			if strings.Contains(line, netconfig.MacNullProjectionPrefix) && len(line) <= 8192 {
				<-childBound
				if nativeBindingValid {
					// Query the real child both before and after parsing. Historical
					// observations cannot authorize a later PID or another launch.
					before, beforeOK := captureNativeFailureChild(nativeBinding.pid, bridgeExe, nativeBinding.nonce)
					projection, parseErr := parseMacNullProjectionLine(line)
					after, afterOK := captureNativeFailureChild(nativeBinding.pid, bridgeExe, nativeBinding.nonce)
					if beforeOK && afterOK && before == nativeBinding && after == nativeBinding && parseErr == nil && recordMacNullProjection(nativeAttempt, nativeBinding, projection) {
						update(func(r *Result) { r.FirewallNullProjection = netconfig.CopyMacNullProjection(projection) })
					}
				}
			}
			if strings.Contains(line, netconfig.MacAnchorProjectionPrefix) && len(line) <= 36*1024 {
				<-childBound
				if nativeBindingValid {
					before, beforeOK := captureNativeFailureChild(nativeBinding.pid, bridgeExe, nativeBinding.nonce)
					projection, parseErr := parseMacAnchorProjectionLine(line)
					after, afterOK := captureNativeFailureChild(nativeBinding.pid, bridgeExe, nativeBinding.nonce)
					if beforeOK && afterOK && before == nativeBinding && after == nativeBinding && parseErr == nil && recordMacAnchorProjection(nativeAttempt, nativeBinding, projection) {
						update(func(r *Result) { r.FirewallAnchorProjection = netconfig.CopyMacAnchorProjection(projection) })
					}
				}
			}
			if i := strings.Index(line, "USB_MAC_INTERFACE_OPERATIONS "); i >= 0 && len(line) <= 4096 {
				if rows, e := interfaceconfig.DecodeMacObservations([]byte(line[i+len("USB_MAC_INTERFACE_OPERATIONS "):])); e == nil {
					update(func(r *Result) { r.InterfaceConfig = rows })
				}
			}
			if i := strings.Index(line, netconfig.BridgeNetworkScriptTimingPrefix); i >= 0 && len(line) <= 1024 {
				<-childBound
				if nativeBindingValid {
					if row, err := netconfig.DecodeBridgeNetworkScriptTiming([]byte(line[i+len(netconfig.BridgeNetworkScriptTimingPrefix):])); err == nil {
						if row.Operation == "diagnostic" {
							recordMacDiagnosticTiming(nativeAttempt, nativeBinding, row)
						}
						update(func(r *Result) {
							if len(r.BridgeNetworkScriptTimings) < 16 {
								r.BridgeNetworkScriptTimings = append(r.BridgeNetworkScriptTimings, row)
							}
						})
					}
				}
			}
			if summary, ok := parseDescriptorSummary(line); ok {
				update(func(r *Result) { r.NCMDescriptors = summary })
			}
			if setting, limit, ok := parseMTUCap(line); ok {
				update(func(r *Result) { r.MTUCap, r.MTUCapFrameLimit = setting, limit })
			}
			if mtu, healthy, ok := parsePathState(line); ok {
				update(func(r *Result) {
					r.EffectiveMTU = mtu
					r.PathMTUWarning = ""
					if !healthy {
						r.PathMTUWarning = "USB_MAC_PATH_CACHE_REFRESH_FAILED"
					}
				})
			}
			if i := strings.Index(line, "USB_GATEWAY_ATTACH luid="); i >= 0 {
				luid, parseErr := strconv.ParseUint(strings.TrimSpace(line[i+len("USB_GATEWAY_ATTACH luid="):]), 10, 64)
				if parseErr == nil {
					if joinHost != nil {
						if e := joinHost(); e != nil {
							update(func(r *Result) { r.Error = "MAC_SHARED_HOST_JOIN_FAILED: " + e.Error() })
							windows.SetEvent(event)
							continue
						}
					}
					if ctx.Err() != nil || CurrentRoot() != root {
						update(func(r *Result) { r.Error = "MAC_TARGET_CHANGED_BEFORE_GATEWAY" })
						windows.SetEvent(event)
						continue
					}
					stop, gateErr := gate.AttachUSB(luid, "10.6.9.2", parentExe, bridgeExe)
					if gateErr == nil {
						gateStop = stop
						proofs, proofErr := gate.OwnedInterfaces()
						if h, ready := usbhost.Proof(); ready {
							proofs = append(proofs, h)
						}
						var proofJSON []byte
						if proofErr == nil {
							proofJSON, proofErr = json.Marshal(proofs)
						}
						if proofErr == nil {
							proofErr = os.WriteFile(filepath.Join(dir, "authorized-usb-interfaces.json"), proofJSON, 0600)
						}
						if proofErr == nil {
							windows.SetEvent(gateEvent)
						} else {
							update(func(r *Result) { r.Error = "MAC_TOPOLOGY_SNAPSHOT_FAILED" })
							windows.SetEvent(event)
						}
					} else {
						update(func(r *Result) { r.Error = "MAC_GATEWAY_PREPARATION_FAILED: " + gateErr.Error() })
						windows.SetEvent(event)
					}
				}
			}
			if strings.Contains(line, "MAC_DHCP_STARTED ") {
				update(func(r *Result) { r.DHCPStarted = true })
			}
			if i := strings.Index(line, "MAC_DHCP_COUNTERS "); i >= 0 {
				for _, part := range strings.Fields(line[i+len("MAC_DHCP_COUNTERS "):]) {
					k, v, ok := strings.Cut(part, "=")
					if !ok {
						continue
					}
					n, er := strconv.ParseUint(v, 10, 64)
					if er != nil {
						continue
					}
					update(func(r *Result) {
						switch k {
						case "discoveries":
							r.DHCPDiscoveries = n
						case "offers":
							r.DHCPOffers = n
						case "acks":
							r.DHCPACKs = n
						}
					})
				}
			}
			if code, detail, exit, ok := parseBridgeStop(line); ok {
				update(func(r *Result) { r.BridgeStopReason, r.BridgeStopDetail, r.BridgeExitCode = code, detail, &exit })
			}
			if strings.Contains(line, "RESULT=STOP error=") {
				update(func(r *Result) { r.BridgeFailureClass = bridgeFailureClass(line) })
			}
			if strings.HasSuffix(line, " "+probecontrol.ReadyMarker) {
				update(func(r *Result) {
					r.Ready = true
					r.Stage = "MAC_RUNNING"
					r.NativeStartupFailure = netconfig.NativeStepDiagnostic{}
					r.NativeDiagnosticSource = ""
					clearNativeFailure(nativeAttempt)
				})
			}
			if strings.Contains(line, "PEER_RESOLVED ") {
				update(func(r *Result) { r.PeerResolved = true })
			}
			if in, outBytes, drops, ok := parseCounters(line); ok {
				now := time.Now()
				update(func(r *Result) {
					r.HeldSeconds = int64(now.Sub(start).Seconds())
					r.Traffic.Add(previousIn, previousOut, in, outBytes, now.Sub(previousTime).Seconds())
					r.BridgeDrops = drops
				})
				previousIn, previousOut, previousTime = in, outBytes, now
			}
		}
		io.Copy(io.Discard, pipeR)
	}()
	if e = cmd.Start(); e != nil {
		close(childBound)
		pipeW.Close()
		<-readerDone
		pipeR.Close()
		out.Error = "MAC_BRIDGE_LAUNCH_FAILED"
		return
	}
	nativeBinding, nativeBindingValid = captureNativeFailureChild(uint32(cmd.Process.Pid), bridgeExe, hex.EncodeToString(token[:]))
	if nativeBindingValid {
		nativeBindingValid = bindNativeFailureChildSource(nativeAttempt, nativeBinding, expectedBridgeSHA)
	}
	update(func(r *Result) {
		r.BridgeStarted = true
		if nativeBindingValid {
			r.BridgeProcessPID = nativeBinding.pid
			r.BridgeProcessCreation = nativeBinding.creation
			r.BridgeProcessBound = true
		}
	})
	close(childBound)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	servicesRetry := serviceRetry{}
	lastEvidence := ""
	lastConnectionEvidence := connectionEvidenceLogState{}
	var lastCoreHealthEvidence [2]connectionEvidenceLogState
	lastRuntimeNetworkEvidence := connectionEvidenceLogState{}
	lastTrustEvidence := connectionEvidenceLogState{}
	lastTimingEvidence := connectionEvidenceLogState{}
	lastPhotoEvidence := connectionEvidenceLogState{}
	lastWPDTraceEvidence := connectionEvidenceLogState{}
	lastPhotoPolicyEvidence := connectionEvidenceLogState{}
	lastNCMDirectEvidence := connectionEvidenceLogState{}
	lastAMDSHoldEvidence := connectionEvidenceLogState{}
	lastConnectionArchiveEvidence := connectionEvidenceLogState{}
	lastNativeUSBEvidence := connectionEvidenceLogState{}
	lastNativePnPEvidence := connectionEvidenceLogState{}
	loops := 0
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	finished := false
	for !finished {
		select {
		case e = <-done:
			finished = true
		case <-ctx.Done():
			endStop := shutdowntrace.Begin(shutdowntrace.PhaseMacBridgeStop)
			windows.SetEvent(event)
			e = <-done
			endStop()
			finished = true
		case <-timer.C:
			if CurrentRoot() != root {
				windows.SetEvent(event)
				e = <-done
				finished = true
				break
			}
			mu.Lock()
			ready := out.Ready
			mu.Unlock()
			loops++
			if ready && loops%5 == 0 {
				ok, queryError := sunshineNativeTCP()
				update(func(r *Result) { r.SunshineTCPObserved = r.SunshineTCPObserved || ok; r.TCPQueryError = queryError })
			}
			if loops%5 == 0 {
				if CoreHealthEvidence != nil {
					for i, row := range CoreHealthEvidence() {
						if i < len(lastCoreHealthEvidence) {
							_ = appendChangedConnectionEvidence(dir, row, &lastCoreHealthEvidence[i], time.Now())
						}
					}
				}
				if ConnectionEvidence != nil {
					_ = appendChangedConnectionEvidence(dir, ConnectionEvidence(), &lastConnectionEvidence, time.Now())
				}
				if RuntimeNetworkEvidence != nil {
					_ = appendChangedConnectionEvidence(dir, RuntimeNetworkEvidence(), &lastRuntimeNetworkEvidence, time.Now())
				}
				if TrustEvidence != nil {
					_ = appendChangedConnectionEvidence(dir, TrustEvidence(), &lastTrustEvidence, time.Now())
				}
				if TimingEvidence != nil {
					_ = appendChangedConnectionEvidence(dir, TimingEvidence(), &lastTimingEvidence, time.Now())
				}
				if PhotoEvidence != nil {
					_ = appendChangedConnectionEvidence(dir, PhotoEvidence(), &lastPhotoEvidence, time.Now())
				}
				for _, item := range []struct {
					evidence func() any
					state    *connectionEvidenceLogState
				}{
					{WPDTraceEvidence, &lastWPDTraceEvidence}, {PhotoPolicyEvidence, &lastPhotoPolicyEvidence}, {NCMDirectEvidence, &lastNCMDirectEvidence}, {AMDSHoldEvidence, &lastAMDSHoldEvidence}, {ConnectionArchiveEvidence, &lastConnectionArchiveEvidence},
					{NativeUSBEvidence, &lastNativeUSBEvidence}, {NativePnPEvidence, &lastNativePnPEvidence},
				} {
					if item.evidence != nil {
						_ = appendChangedConnectionEvidence(dir, item.evidence(), item.state, time.Now())
					}
				}
				mu.Lock()
				state := out
				mu.Unlock()
				evidence := map[string]any{"stage": state.Stage, "parent_executable": boundedServiceText(parentExe), "bridge_executable": boundedServiceText(bridgeExe), "services_ready": state.ServicesReady, "services_error": state.ServicesError, "service_retry_failures": servicesRetry.Failures, "gateway": boundedGatewayEvidence(usbgateway.Evidence()), "shared_host": usbhost.Details()}
				proofs, proofError := gate.OwnedInterfaces()
				if h, ok := usbhost.Proof(); ok {
					proofs = append(proofs, h)
				}
				if proofError == nil {
					evidence["usb_network"] = usbaddress.NativeDetails(proofs)
				} else {
					evidence["usb_network"] = map[string]any{"error": "USB_OWNED_INTERFACE_QUERY_FAILED"}
				}
				if DeveloperStatus != nil {
					evidence["developer"] = DeveloperStatus()
				}
				if body, er := json.Marshal(evidence); er == nil && string(body) != lastEvidence {
					if er = appendUpgradeEvidence(dir, body); er == nil {
						lastEvidence = string(body)
					}
				}
			}
			if ready && servicesRetry.due(time.Now()) {
				er := func() error {
					j, er := record(dir)
					if er != nil {
						return fmt.Errorf("FILE_OWNED_ADAPTER_UNCONFIRMED: %w", er)
					}
					if j.Status != "ACTIVE" || ctx.Err() != nil || CurrentRoot() != root {
						return fmt.Errorf("FILE_OWNED_ADAPTER_NOT_ACTIVE")
					}
					var nativeProof usbaddress.InterfaceProof
					if netconfig.ResidentFirewallEnabled() {
						if j.Version != bridge.ResidentSessionVersion {
							return fmt.Errorf("FILE_RESIDENT_SESSION_UNPROVEN")
						}
						nativeProof, er = netconfig.ResolveMacProofNative(ctx, j.GUID)
						if er != nil {
							return er
						}
						coreBatch, sourceErr := connectioninstall.PinCoreSourceBatchSelf()
						if sourceErr != nil {
							return sourceErr
						}
						defer coreBatch.Close()
						verifyReadOwner := func() error {
							if ctx.Err() != nil || CurrentRoot() != root {
								return fmt.Errorf("FILE_RESIDENT_ROOT_CHANGED")
							}
							fresh, e := record(dir)
							if e != nil || bridge.VerifyLiveResidentSession(j, fresh) != nil {
								return fmt.Errorf("FILE_RESIDENT_SESSION_CHANGED")
							}
							child, valid := captureNativeFailureChild(nativeBinding.pid, bridgeExe, nativeBinding.nonce)
							if !nativeBindingValid || !valid || child != nativeBinding {
								return fmt.Errorf("FILE_RESIDENT_CHILD_CHANGED")
							}
							proof, e := netconfig.ResolveMacProofNative(ctx, j.GUID)
							if e != nil || proof != nativeProof {
								return fmt.Errorf("FILE_RESIDENT_INTERFACE_CHANGED")
							}
							return coreBatch.Refresh()
						}
						if er = netconfig.VerifyResidentMacFirewall(ctx, parent, nativeProof, verifyReadOwner); er != nil {
							return fmt.Errorf("FILE_FIREWALL_PREPARATION_FAILED: %w", er)
						}
						if er = netconfig.VerifyResidentCoreFirewall(ctx, parent, nativeProof, "10.6.9.2", parentExe, verifyReadOwner); er != nil {
							return fmt.Errorf("USB_CORE_PERMISSION_FAILED: %w", er)
						}
						if er = coreBatch.Complete(); er != nil {
							return er
						}
					} else if netconfig.CombinedLegacyNetworkEnabled() && !netconfig.NativeNetworkEnabled() {
						// Same proven peer/session stage as the old two calls. Keep the
						// exact legacy token cleanup and core metadata suffix/readback.
						pin, pinErr := connectioninstall.PinCoreSourceBatchSelf()
						if pinErr != nil {
							return fmt.Errorf("USB_CORE_EXECUTABLE_UNVERIFIED: %w", pinErr)
						}
						defer pin.Close()
						proof, proofErr := netconfig.ResolveMacProofNative(ctx, j.GUID)
						if proofErr != nil {
							return proofErr
						}
						owner := func() error {
							if ctx.Err() != nil || CurrentRoot() != root || !nativeBindingValid {
								return fmt.Errorf("FILE_LEGACY_BATCH_OWNER_CHANGED")
							}
							fresh, e := bridge.ReadOrdinaryOwnedSession(dir)
							if e != nil || bridge.VerifyLiveOrdinarySession(j, fresh) != nil {
								return fmt.Errorf("FILE_LEGACY_BATCH_SESSION_CHANGED")
							}
							child, valid := captureNativeFailureChild(nativeBinding.pid, bridgeExe, nativeBinding.nonce)
							if !valid || child != nativeBinding {
								return fmt.Errorf("FILE_LEGACY_BATCH_CHILD_CHANGED")
							}
							current, e := netconfig.ResolveMacProofNative(ctx, j.GUID)
							if e != nil || current != proof {
								return fmt.Errorf("FILE_LEGACY_BATCH_INTERFACE_CHANGED")
							}
							return pin.Refresh()
						}
						script, planErr := netconfig.LegacyMacServiceScript(j.GUID, j.Token, parentExe)
						if planErr != nil {
							return fmt.Errorf("USB_CORE_PERMISSION_FAILED: %w", planErr)
						}
						if er = netconfig.ExecuteCombinedLegacyNetwork(ctx, script, owner, func(c context.Context, script string) error {
							return netconfig.RunLegacyRoleContext(c, "mac_services", script, l)
						}); er != nil {
							return fmt.Errorf("USB_CORE_PERMISSION_FAILED: %w", er)
						}
						if er = pin.Complete(); er != nil {
							return er
						}
					} else {
						if netconfig.NativeNetworkEnabled() {
							nativeProof, er = netconfig.ResolveMacProofNative(ctx, j.GUID)
							if er == nil {
								er = netconfig.EnsureMacFileRuleNative(ctx, nativeProof, j.Token, l)
							}
						} else {
							script, planErr := netconfig.FileReceiverRuleForProfile(j.GUID, j.Token, true, "unified")
							er = planErr
							if er == nil {
								er = netconfig.RunLegacyRoleContext(context.Background(), "mac_services", script, l)
							}
						}
						if er != nil {
							return fmt.Errorf("FILE_FIREWALL_PREPARATION_FAILED: %w", er)
						}
						if er = connectioninstall.Verify(parentExe); er != nil {
							return fmt.Errorf("USB_CORE_EXECUTABLE_UNVERIFIED: %w", er)
						}
						if netconfig.NativeNetworkEnabled() {
							er = netconfig.EnsureCoreServicesNative(ctx, nativeProof, "10.6.9.2", parentExe, l)
						} else {
							coreScript, planErr := netconfig.CoreServicesRule(j.GUID, "10.6.9.2", parentExe)
							er = planErr
							if er == nil {
								er = netconfig.RunLegacyRoleContext(context.Background(), "mac_services", coreScript, l)
							}
						}
						if er != nil {
							return fmt.Errorf("USB_CORE_PERMISSION_FAILED: %w", er)
						}
					}
					serviceGuard := func() bool { return ctx.Err() == nil && CurrentRoot() == root }
					service := &usbservice.Handler{PeerIP: "10.6.9.2", Guard: serviceGuard}
					test, er := throughput.NewBrowserForDevice(ctx, "Mac", "10.6.9.2", "10.6.9.1:10690", serviceGuard, func(v throughput.Report) { update(func(r *Result) { r.Benchmark = v }) })
					if er != nil {
						return fmt.Errorf("FILE_SPEED_PREPARATION_FAILED: %w", er)
					}
					service.Benchmark = test
					stop, er := usbhttp.Register(ctx, "10.6.9.1:10690", "10.6.9.2", localMaintenanceHandler(service, serviceGuard))
					if er != nil {
						test.Close()
						return fmt.Errorf("FILE_LISTENER_UNAVAILABLE: %w", er)
					}
					stopServices, speedTest = stop, test
					throughput.SetDeviceCurrent("Mac", test)
					update(func(r *Result) {
						r.ServicesReady = true
						r.BenchmarkURL = "http://10.6.9.1:10690/speed/"
						r.ServicesError = ""
					})
					l.Print("MAC_USB_SERVICES_READY port=10690")
					firewallShadowOnce.tryStart(ctx, netconfig.FirewallShadowEnabled(), !netconfig.ResidentFirewallEnabled() && !netconfig.NativeNetworkEnabled(), nativeBindingValid, func() {
						observeLegacyMacFirewallShadow(ctx, dir, root, bridgeExe, parentExe, nativeAttempt, nativeBinding, j)
					})
					return nil
				}()
				servicesRetry.complete(time.Now(), er)
				if er != nil {
					l.Printf("MAC_USB_SERVICES_RETRY attempt=%d error=%v", servicesRetry.Failures, er)
					update(func(r *Result) { r.ServicesError = string([]rune(er.Error())[:min(512, len([]rune(er.Error())))]) })
				}
			}
		}
	}
	if stopServices != nil {
		endServices := shutdowntrace.Begin(shutdowntrace.PhaseMacServicesStop)
		stopServices()
		endServices()
	}
	pipeW.Close()
	<-readerDone
	pipeR.Close()

	if e != nil && out.Error == "" {
		out.Error = "MAC_BRIDGE_ENDED_WITH_ERROR"
	}
	// A crash, kill or panic before BRIDGE_STOP is written still leaves the OS status.
	var exitErr *exec.ExitError
	if errors.As(e, &exitErr) && out.BridgeExitCode == nil {
		code := exitErr.ExitCode()
		out.BridgeExitCode = &code
		if out.BridgeStopReason == "" {
			out.BridgeStopReason = "BRIDGE_EXITED_WITHOUT_STOP_LINE"
		}
	}
	cleanup := runMacCleanup(func() error {
		defer shutdowntrace.Begin(shutdowntrace.PhaseMacSessionRecovery)()
		return Recover(parent)
	}, func() error {
		// Detach cancels the session, so restoration owns its bounded lifetime.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		defer shutdowntrace.Begin(shutdowntrace.PhaseMacMTURestore)()
		return usbhost.ResetMacMTU(cleanupCtx)
	})
	if er := cleanup.RecoveryError; er != nil {
		if nativeBindingValid {
			recordMacCleanupFailure(nativeAttempt, nativeBinding, er)
		}
		out.Error = er.Error()
	}
	if er := cleanup.MTUError; er != nil {
		out.Error = "MAC_SOURCE_MTU_RESTORE_FAILED: " + er.Error()
	}
	out.CleanupConfirmed = cleanup.confirmed()
	out.Stage = "MAC_SESSION_ENDED"
	out.ServicesReady = false
	return
}

// Remote maintenance shares only the currently owned, active Mac USB adapter.
func MaintenanceGUID(parent string) string {
	r, e := record(filepath.Join(parent, runtimeName))
	if e != nil || r.Status != "ACTIVE" || CurrentRoot() == "" {
		return ""
	}
	return r.GUID
}

// RecordUpgradeEvidence writes bounded classifications to a separate fixed log.
// Legacy USB diagnostics append service.log, while installer.log may rotate.
func RecordUpgradeEvidence(parent, version, stage, problem string) error {
	b, e := json.Marshal(map[string]string{"version": version, "stage": stage, "error": problem})
	if e != nil || len(b) > 8192 {
		return fmt.Errorf("upgrade evidence exceeds bound")
	}
	return recordRuntimeEvidence(parent, b)
}

// Keep the last verified exit stage available after the next launch, including
// when ordinary log prefixes are dropped by the bounded USB transport.
func RecordProgramExitEvidence(parent, version, stage string) error {
	return recordProgramExitForRuntime(parent, runtimeName, version, stage, exitrecord.Write, appendUpgradeEvidence)
}

// RecordCoreEvidence writes one bounded diagnostic row to the runtime logs
// that exist now; later rows come from CoreHealthEvidence while a session runs.
func RecordCoreEvidence(parent string, row any) error {
	b, e := json.Marshal(row)
	if e != nil || len(b) > 8192 {
		return fmt.Errorf("upgrade evidence exceeds bound")
	}
	return recordRuntimeEvidence(parent, b)
}

func recordRuntimeEvidence(parent string, b []byte) error {
	names, e := recoveryRuntimeNames(parent)
	if e != nil {
		return e
	}
	for _, name := range names {
		dir := filepath.Join(parent, name)
		if !safeRuntimeDirectory(dir) {
			continue
		}
		if e := appendUpgradeEvidence(dir, b); e != nil {
			return e
		}
	}
	return nil
}

func SharedWindowsHostReady() bool { _, ready := usbhost.Proof(); return ready }

// PrepareSharedHostDLL extracts only the already verified embedded runtime.
func PrepareSharedHostDLL(parent string, payload, manifest []byte) (string, error) {
	return PrepareSharedHostDLLArchive(parent, ArchiveBytes(payload), manifest)
}
func PrepareSharedHostDLLArchive(parent string, payload RuntimeArchive, manifest []byte) (string, error) {
	_, e := unpackArchive(parent, payload, manifest)
	if e != nil {
		return "", e
	}
	return dependencies.Ensure(context.Background(), "wintun")
}
