//go:build windows && amd64

package bridgeworker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/diagnostics/bench"
	"suhang/usbnet/internal/diagnostics/latencyprobe"
	"suhang/usbnet/internal/diagnostics/logfile"
	"suhang/usbnet/internal/diagnostics/memorydiag"
	"suhang/usbnet/internal/diagnostics/mtutrial"
	"suhang/usbnet/internal/diagnostics/probecontrol"
	"suhang/usbnet/internal/diagnostics/rawusb"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/macdhcp"
	"suhang/usbnet/internal/transport/ncm"
	"suhang/usbnet/internal/transport/packetbuffer"
	"suhang/usbnet/internal/transport/parentlifetime"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/usbwait"
	"suhang/usbnet/internal/transport/wintun"
	"suhang/usbnet/internal/transport/winusb"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var version = buildinfo.Version + "-shared-subnet"

func run(dir string, l *log.Logger) (runErr error) {
	reportInterfaceOperations := func() {
		rows := []interfaceconfig.OperationTiming{}
		for _, row := range interfaceconfig.ObservationsSnapshot() {
			if row.Role == "mac" {
				rows = append(rows, row)
			}
		}
		if b, e := json.Marshal(rows); e == nil && len(b) <= 4096 {
			l.Printf("USB_MAC_INTERFACE_OPERATIONS %s", b)
		}
	}
	defer reportInterfaceOperations()
	memorydiag.RecordStage("bridge_run_enter")
	nativeNS, goNS, copyErr := wintun.VerifyNativeCopy()
	if copyErr != nil {
		return fmt.Errorf("native copy self-test: %w", copyErr)
	}
	l.Printf("NATIVE_COPY_SELFTEST_OK rtl_ns_per_1500=%d go_ns_per_1500=%d", nativeNS, goNS)
	profile := flag.String("address-profile", usbaddress.Legacy, "fixed USB address profile")
	nativeNetwork := flag.Bool("native-network", false, "use the protected parent-selected native network comparison")
	residentFirewall := flag.Bool("resident-firewall", false, "fixed scoped resident firewall selected by verified core")
	combinedLegacy := flag.Bool("combined-legacy-network", false, "combine existing same-stage legacy scripts selected by verified core")
	internetRoot := flag.String("internet-root", "", "core-selected current Mac USB identity")
	externalWintun := flag.String("wintun-path", "", "verified external Wintun DLL")
	moduleHold := flag.Bool("wintun-module-hold", false, "verified core-selected module lifecycle experiment")
	coreExecutable := flag.String("core-exe", "", "actual protected SCM parent executable for resident permissions")
	ownedDadZero := flag.Bool("owned-dad-zero", false, "independent owned DadTransmits-only change")
	dadZero := flag.Bool("dad-zero", false, "owned parent-selected DAD comparison")
	persistentConfig := flag.Bool("persistent-config", false, "owned parent-selected persistent interface comparison")
	sharedHost := flag.Bool("shared-host", false, "verified shared Windows host address")
	gateEvent := flag.String("gateway-ready-event", "", "owned USB application gate readiness barrier")
	stopEvent := flag.String("stop-event", "", "owned launcher's graceful stop event")
	parentHandle := flag.Uint64("parent-handle", 0, "actual inherited launcher process handle")
	parentPID := flag.Uint64("parent-pid", 0, "actual kernel launcher identity")
	parentCreation := flag.Uint64("parent-creation", 0, "actual launcher process creation time")
	txDepth := flag.Int("tx-depth", 16, "bounded asynchronous USB OUT depth (1-16)")
	batchRequested := flag.Int("batch-max", 16, "maximum already-ready frames per NTB (1-32; no timer)")
	readDepth := flag.Int("read-depth", 16, "pending USB IN requests (4-16)")
	flag.Parse()
	launchPhase := "mac_launch_validate"
	var firstFailure netconfig.FirstMacStartupFailure
	reportFirstFailure := func(cause error) {
		if *residentFirewall || *ownedDadZero || *moduleHold {
			if message, ok := firstFailure.Capture(launchPhase, cause); ok {
				l.Printf("%s%s", netconfig.NativeFailurePrefix, message)
			}
		}
	}
	defer func() { reportFirstFailure(runErr) }()
	netconfig.SetNativeNetworkEnabled(*nativeNetwork)
	netconfig.SetResidentFirewallEnabled(*residentFirewall)
	netconfig.SetCombinedLegacyNetworkEnabled(*combinedLegacy)
	interfaceconfig.SetOwnedDADZeroEnabled(*ownedDadZero)
	interfaceconfig.SetDADZeroEnabled(*dadZero)
	interfaceconfig.SetPersistentEnabled(*persistentConfig)
	if e := interfaceconfig.ValidateMacOptimizationLaunch(*dadZero, *persistentConfig, *nativeNetwork, *sharedHost, *profile, *gateEvent, filepath.Base(dir)); e != nil {
		return e
	}
	if e := interfaceconfig.ValidateMacOwnedDADLaunch(*ownedDadZero, *sharedHost, *profile, *gateEvent, filepath.Base(dir)); e != nil {
		return e
	}
	if *ownedDadZero && (*nativeNetwork || *persistentConfig || *dadZero) {
		return fmt.Errorf("USB_MAC_OWNED_DAD_EXPERIMENT_COMBINATION_REJECTED")
	}
	if *txDepth < 1 || *txDepth > 16 || *batchRequested < 1 || *batchRequested > 32 || *readDepth < 4 || *readDepth > 16 {
		return fmt.Errorf("invalid transport limits")
	}
	addresses, e := usbaddress.Lookup(*profile)
	if e != nil {
		return e
	}
	copy(ncm.WindowsIP[:], net.ParseIP(addresses.Windows).To4())
	copy(ncm.MacIP[:], net.ParseIP(addresses.Peer).To4())
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var monitor sync.WaitGroup
	defer monitor.Wait()
	defer cancel()
	boundParent := *parentHandle != 0 || *parentPID != 0 || *parentCreation != 0
	boundLink := parentlifetime.Link{Handle: windows.Handle(*parentHandle), PID: uint32(*parentPID), Creation: *parentCreation}
	if e := netconfig.ValidateCombinedLegacyMacLaunch(*combinedLegacy, *nativeNetwork, *residentFirewall, *sharedHost, boundParent, *profile, *gateEvent, filepath.Base(dir)); e != nil {
		return e
	}
	if e := netconfig.ValidateMacCoreSourceLaunch(*residentFirewall, *moduleHold, *nativeNetwork, *persistentConfig, *dadZero, *sharedHost, boundParent, *profile, *gateEvent, filepath.Base(dir), *coreExecutable); e != nil {
		return e
	}
	if boundParent && (*stopEvent == "" || *parentPID > uint64(^uint32(0))) {
		return fmt.Errorf("USB_PARENT_LAUNCH_ARGUMENTS_INVALID")
	}
	if *stopEvent != "" {
		if !regexp.MustCompile(`^(Local|Global)\\SuhangUSBBridgeStop-[a-f0-9]{24}$`).MatchString(*stopEvent) {
			return fmt.Errorf("invalid owned stop event")
		}
		name, _ := windows.UTF16PtrFromString(*stopEvent)
		event, err := windows.OpenEvent(windows.SYNCHRONIZE, false, name)
		if err != nil {
			return err
		}
		if boundParent {
			link := parentlifetime.Link{Handle: windows.Handle(*parentHandle), PID: uint32(*parentPID), Creation: *parentCreation}
			if err := link.Validate(); err != nil {
				windows.CloseHandle(event)
				return err
			}
			defer link.Close()
			defer windows.CloseHandle(event)
			join, err := link.Watch(ctx, cancel, event)
			if err != nil {
				return err
			}
			defer join()
		} else {
			monitor.Add(1)
			go func(eventCtx context.Context) {
				defer monitor.Done()
				defer windows.CloseHandle(event)
				for eventCtx.Err() == nil {
					status, err := windows.WaitForSingleObject(event, 50)
					if err != nil || status == windows.WAIT_OBJECT_0 {
						cancel()
						return
					}
				}
			}(ctx)
		}
	}
	launchPhase = "mac_parent_source"
	var verifyCoreOwner func() error
	var coreSource *connectioninstall.CoreSourceBatch
	if *residentFirewall || *moduleHold {
		var coreErr error
		coreSource, coreErr = connectioninstall.PinCoreSourceBatchParent(*coreExecutable, boundLink)
		if coreErr != nil {
			return coreErr
		}
		defer coreSource.Close()
		verifyCoreOwner = coreSource.Refresh
	}
	// The inherited actual kernel parent and fixed SCM source must be verified
	// before this irreversible per-process selection. No environment/UI setter.
	if *moduleHold {
		if !boundParent || coreSource == nil || coreSource.Complete() != nil {
			return fmt.Errorf("USB_MAC_MODULE_HOLD_PARENT_UNPROVEN")
		}
		wintun.SetModuleLifetimeHoldEnabled(true)
	}
	l.Printf("USB_WINTUN_MODULE_LIFETIME enabled=%t pinned_modules=%d", wintun.ModuleLifetimeSnapshot().Enabled, wintun.ModuleLifetimeSnapshot().PinnedModules)
	var dadScope interfaceconfig.Scope
	configDir := filepath.Dir(dir)
	var dadApplied bool
	launchPhase = "mac_runtime_acquire"
	dll := *externalWintun
	if dll == "" {
		return fmt.Errorf("EXTERNAL_WINTUN_REQUIRED")
	}
	if err := netconfig.VerifyWintun(dll, l); err != nil {
		return err
	}
	release, err := winusb.OwnRuntime()
	if err != nil {
		return err
	}
	defer release()
	launchPhase = "mac_usb_open"
	var topology []usbaddress.InterfaceProof
	var device *winusb.NCMDevice
	if *profile == usbaddress.Unified {
		device, err = winusb.InitializeNCMWithTrial(0, false, 0, l)
	} else {
		device, err = winusb.InitializeNCM(0, false, 0, l)
	}
	if err != nil {
		return err
	}
	defer device.Close()
	var initialControl, initialData string
	if netconfig.MacLaunchNeedsUSBPair(*dadZero, *persistentConfig, *residentFirewall, *ownedDadZero) {
		launchPhase = "mac_usb_pair_capture"
		nodes, e := winusb.Enumerate(l)
		if e != nil {
			return e
		}
		initialControl, initialData, e = winusb.Pair(nodes, 0, false)
		if e != nil {
			return e
		}
		if !device.MatchesOpenedPair(initialControl, initialData) {
			return fmt.Errorf("USB_MAC_OPENED_USB_PAIR_CHANGED")
		}
	}

	memorydiag.RecordStage("winusb_ncm_initialized")
	mtu := min(1500, int(device.MaxSegment)-14)
	if mtu < 576 {
		return fmt.Errorf("invalid segment size")
	}
	var releaseTopology func()
	if *persistentConfig {
		releaseTopology, err = usbaddress.ConfigurationLock(ctx)
		if err != nil {
			return err
		}
		defer releaseTopology()
	}
	// Consume an old Dad-only obligation solely after complete native absence,
	// before a new official factory can reuse the fixed GUID with a new LUID.
	launchPhase = "mac_dad_originals"
	ownedDadUsable := true
	oldDadObligations, priorDadErr := interfaceconfig.ReadOwnedDADObligations(configDir)
	if priorDadErr != nil {
		ownedDadUsable = false
		l.Printf("USB_MAC_OWNED_DAD fallback=true code=ORIGINAL_UNREADABLE")
	}
	for _, old := range oldDadObligations {
		if old.Scope.Role == "mac" {
			if e := interfaceconfig.RetireOwnedDADAbsent(ctx, configDir, old); e != nil {
				ownedDadUsable = false
				l.Printf("USB_MAC_OWNED_DAD fallback=true code=PRIOR_ABSENCE_UNPROVEN")
			}
		}
	}
	launchPhase = "mac_factory_open"
	var retained *interfaceconfig.RetainedSecondary
	var tun *wintun.Device
	usbOwner := func(scope interfaceconfig.Scope) error {
		if scope.Role != "mac" || !strings.EqualFold(scope.GUID, interfaceconfig.MacGUID) || ctx.Err() != nil {
			return fmt.Errorf("USB_MAC_PERSISTENT_USB_OWNER_UNPROVEN")
		}
		nodes, e := winusb.Enumerate(l)
		if e != nil {
			return e
		}
		cp, dp, e := winusb.Pair(nodes, 0, false)
		if e != nil || cp != initialControl || dp != initialData || !device.MatchesOpenedPair(cp, dp) {
			return fmt.Errorf("USB_MAC_PERSISTENT_USB_ATTACHMENT_CHANGED")
		}
		return nil
	}
	profiles := func(scope interfaceconfig.Scope) interfaceconfig.ProfileOps {
		return interfaceconfig.WintunProfileOps(scope, func() error { return usbOwner(scope) }, l)
	}
	if *persistentConfig {
		if _, _, e := interfaceconfig.ReadPersistentOriginalSnapshot(configDir, "mac"); e != nil {
			return e
		}
	}
	if *persistentConfig {
		if mtu != 1500 {
			return fmt.Errorf("USB_MAC_PERSISTENT_MTU_PLAN_REQUIRED")
		}
		var found bool
		tun, retained, found, err = interfaceconfig.OpenPersistentMac(ctx, configDir, dll, usbOwner, profiles)
		if err != nil {
			return err
		}
		if !found {
			tun, err = wintun.Open(dll)
		}
	} else {
		tun, err = wintun.Open(dll)
	}
	if err != nil {
		return err
	}
	if *persistentConfig && retained == nil && !tun.FactoryHandleHeld() {
		tun.Close()
		return fmt.Errorf("USB_MAC_PERSISTENT_FIRST_FACTORY_REQUIRED")
	}
	defer tun.Close()
	launchPhase = "mac_gateway_wait"
	if *gateEvent != "" {
		if !regexp.MustCompile(`^Local\\USBLinkGatewayReady-[a-f0-9]{24}$`).MatchString(*gateEvent) {
			return fmt.Errorf("invalid gateway event")
		}
		event, e := windows.OpenEvent(windows.SYNCHRONIZE, false, windows.StringToUTF16Ptr(*gateEvent))
		if e != nil {
			return e
		}
		defer windows.CloseHandle(event)
		l.Printf("USB_GATEWAY_ATTACH luid=%d", tun.LUID)
		deadline := time.Now().Add(30 * time.Second)
		ready := false
		for ctx.Err() == nil && time.Now().Before(deadline) {
			status, e := windows.WaitForSingleObject(event, 50)
			if e != nil {
				return e
			}
			if status == windows.WAIT_OBJECT_0 {
				ready = true
				break
			}
		}
		if !ready {
			return fmt.Errorf("USB_GATEWAY_READINESS_FAILED")
		}
		f, e := os.Open(filepath.Join(dir, "authorized-usb-interfaces.json"))
		if e != nil {
			return fmt.Errorf("USB_TOPOLOGY_SNAPSHOT_UNAVAILABLE: %w", e)
		}
		snapshot, e := io.ReadAll(io.LimitReader(f, 4097))
		f.Close()
		if e != nil || len(snapshot) > 4096 {
			return fmt.Errorf("USB_TOPOLOGY_SNAPSHOT_INVALID")
		}
		decoder := json.NewDecoder(strings.NewReader(string(snapshot)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&topology) != nil || len(topology) > 4 {
			return fmt.Errorf("USB_TOPOLOGY_SNAPSHOT_INVALID")
		}
		if e = usbaddress.VerifyProofs(topology); e != nil {
			return e
		}
		var tail any
		if decoder.Decode(&tail) != io.EOF {
			return fmt.Errorf("USB_TOPOLOGY_SNAPSHOT_INVALID")
		}
	}
	launchPhase = "mac_topology_verify"
	// Never hold the configuration lock while the parent is joining a host
	// generation: host preparation itself needs this lock.
	if releaseTopology == nil {
		releaseTopology, err = usbaddress.ConfigurationLock(ctx)
		if err != nil {
			return err
		}
		defer releaseTopology()
	}
	if err = usbaddress.VerifyProofs(topology); err != nil {
		return err
	}
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	setup, cleanup, err := netconfig.ScriptsForProfile(tun.Index, tun.GUID.String(), mtu, hex.EncodeToString(token), *profile)
	if *profile == usbaddress.Unified {
		setup, cleanup, err = netconfig.SharedProfileScripts(tun.Index, tun.GUID.String(), mtu, hex.EncodeToString(token), topology)
	}
	if *sharedHost {
		setup, cleanup, err = netconfig.VirtualHostMacScripts(tun.Index, tun.GUID.String(), mtu, hex.EncodeToString(token), topology)
	}
	if err != nil {
		return err
	}
	l.Printf("owned adapter index=%d guid=%s MTU=%d firewall token=%x", tun.Index, tun.GUID.String(), mtu, token)
	session := bridge.NewOwnedSession(tun.GUID.String(), hex.EncodeToString(token))
	if *residentFirewall {
		session.Version = bridge.ResidentSessionVersion
	}
	ordinaryCleanupProof := usbaddress.InterfaceProof{Index: tun.Index, LUID: tun.LUID, GUID: tun.GUID.String()}
	record := func() error {
		b, e := json.Marshal(session)
		if e != nil {
			return e
		}
		if session.Version == bridge.ResidentSessionVersion {
			return bridge.WriteResidentOwnedSession(dir, session)
		}
		if session.Version == bridge.RetainedSessionVersion {
			return bridge.WriteRetainedOwnedSession(dir, session)
		}
		return os.WriteFile(filepath.Join(dir, "owned-session.json"), b, 0600)
	}
	launchPhase = "mac_session_write"
	// If ownership cannot be persisted, no IP/firewall configuration is attempted.
	if err = record(); err != nil {
		return err
	}
	verifyHeldSession := func(checkCtx context.Context) error {
		if checkCtx.Err() != nil {
			return checkCtx.Err()
		}
		if !tun.FactoryHandleHeld() || tun.Index != ordinaryCleanupProof.Index || tun.LUID != ordinaryCleanupProof.LUID || tun.GUID.String() != ordinaryCleanupProof.GUID {
			return fmt.Errorf("USB_MAC_CURRENT_FACTORY_LEASE_CHANGED")
		}
		var observed bridge.OwnedSession
		var e error
		if session.Version == bridge.ResidentSessionVersion {
			observed, e = bridge.ReadResidentOwnedSession(dir)
			if e == nil {
				e = bridge.VerifyLiveResidentSession(session, observed)
			}
		} else {
			observed, e = bridge.ReadOrdinaryOwnedSession(dir)
			if e == nil {
				e = bridge.VerifyLiveOrdinarySession(session, observed)
			}
		}
		if e != nil {
			return e
		}
		return checkCtx.Err()
	}
	var ownedDadIdentity interfaceconfig.OwnedDADIdentity
	var ownedDadPrepared bool
	var residentInstance string
	verifyAttachedSession := func(checkCtx context.Context) error {
		if e := verifyHeldSession(checkCtx); e != nil {
			return e
		}
		nodes, e := winusb.Enumerate(l)
		if e != nil {
			return e
		}
		cp, dp, e := winusb.Pair(nodes, 0, false)
		if e != nil || cp != initialControl || dp != initialData || !device.MatchesOpenedPair(cp, dp) {
			return fmt.Errorf("USB_MAC_CURRENT_USB_ATTACHMENT_CHANGED")
		}
		if residentInstance == "" {
			return fmt.Errorf("USB_MAC_CURRENT_TYPED_INSTANCE_REQUIRED")
		}
		if e = netconfig.VerifyOwnedMacRecreatedNative(tun.Index, tun.LUID, residentInstance); e != nil {
			return e
		}
		return verifyHeldSession(checkCtx)
	}
	defer func() {
		reportFirstFailure(runErr)
		launchPhase = "mac_session_cleanup"
		var cleanupErr error
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancelCleanup()
		if ownedDadPrepared {
			restore, restoreErr := interfaceconfig.OwnedDADRestoreRequested(configDir)
			cleanupErr = errors.Join(cleanupErr, restoreErr)
			if restoreErr == nil && restore {
				cleanupErr = errors.Join(cleanupErr, interfaceconfig.RestoreOwnedDADZero(cleanupCtx, configDir, ownedDadIdentity, func() error { return verifyAttachedSession(cleanupCtx) }))
			}
		}
		if dadApplied && retained == nil {
			cleanupOwner := func() error {
				if !tun.FactoryHandleHeld() || tun.Index != dadScope.Index || tun.LUID != dadScope.LUID || !strings.EqualFold(tun.GUID.String(), dadScope.GUID) {
					return fmt.Errorf("USB_MAC_DAD_CLEANUP_OWNER_UNPROVEN")
				}
				return netconfig.VerifyOwnedWintunRecoveryIdentityNative(cleanupCtx, netconfig.OwnedProfileRecoveryIdentity{Role: "mac", GUID: dadScope.GUID, Index: dadScope.Index, LUID: dadScope.LUID}, func() error {
					if !tun.FactoryHandleHeld() || tun.Index != dadScope.Index || tun.LUID != dadScope.LUID {
						return fmt.Errorf("USB_MAC_DAD_FACTORY_LEASE_CHANGED")
					}
					return nil
				})
			}
			cleanupErr = errors.Join(cleanupErr, interfaceconfig.RestoreDADZero(cleanupCtx, configDir, dadScope, cleanupOwner))
		}
		if *residentFirewall {
			cleanupErr = errors.Join(cleanupErr, verifyHeldSession(cleanupCtx))
		} else if *nativeNetwork {
			if retained != nil {
				p := usbaddress.InterfaceProof{Index: tun.Index, LUID: tun.LUID, GUID: tun.GUID.String()}
				cleanupErr = errors.Join(cleanupErr, netconfig.CleanupRetainedMacSessionNative(cleanupCtx, p, session.Token, func() error { return retained.VerifyCleanupAddress(cleanupCtx, p) }, l))
			} else {
				verifyOrdinarySession := func() error {
					if err := cleanupCtx.Err(); err != nil {
						return err
					}
					if !tun.FactoryHandleHeld() || tun.Index != ordinaryCleanupProof.Index || tun.LUID != ordinaryCleanupProof.LUID || tun.GUID.String() != ordinaryCleanupProof.GUID {
						return fmt.Errorf("USB_MAC_CLEANUP_FACTORY_LEASE_CHANGED")
					}
					observed, err := bridge.ReadOrdinaryOwnedSession(dir)
					if err != nil {
						return err
					}
					if err = bridge.VerifyLiveOrdinarySession(session, observed); err != nil {
						return err
					}
					if !tun.FactoryHandleHeld() || tun.Index != ordinaryCleanupProof.Index || tun.LUID != ordinaryCleanupProof.LUID || tun.GUID.String() != ordinaryCleanupProof.GUID {
						return fmt.Errorf("USB_MAC_CLEANUP_FACTORY_LEASE_CHANGED")
					}
					return cleanupCtx.Err()
				}
				cleanupErr = errors.Join(cleanupErr, netconfig.CleanupOwnedMacSessionNative(cleanupCtx, ordinaryCleanupProof, session.Token, verifyOrdinarySession, l))
			}
		} else {
			cleanupErr = errors.Join(cleanupErr, runBridgeNetworkScript(cleanupCtx, "cleanup", cleanup, l))
		}
		if retained != nil {
			cleanupErr = errors.Join(cleanupErr, retained.Close())
		} else {
			var closeInstance string
			if *moduleHold {
				closeErr := verifyHeldSession(cleanupCtx)
				if closeErr == nil {
					closeErr = coreSource.Refresh()
				}
				if closeErr == nil {
					closeInstance, closeErr = netconfig.CaptureOwnedMacNative(ordinaryCleanupProof.Index, ordinaryCleanupProof.LUID, false)
				}
				if closeErr == nil {
					closeErr = verifyHeldSession(cleanupCtx)
				}
				if closeErr == nil {
					closeErr = coreSource.Refresh()
				}
				cleanupErr = errors.Join(cleanupErr, closeErr)
			}
			tun.Close()
			if *moduleHold {
				l.Printf("USB_WINTUN_MODULE_LIFETIME enabled=%t pinned_modules=%d", wintun.ModuleLifetimeSnapshot().Enabled, wintun.ModuleLifetimeSnapshot().PinnedModules)
				cleanupErr = errors.Join(cleanupErr, netconfig.WaitOwnedMacCloseAbsentNative(cleanupCtx, ordinaryCleanupProof.Index, ordinaryCleanupProof.LUID, closeInstance, l))
			}
		} // All packet workers have joined before cleanup.
		check, e := netconfig.VerifyCleanup(session.GUID, session.Token)
		if e == nil {
			if *residentFirewall {
				e = netconfig.WaitResidentMacAdapterAbsentNative(cleanupCtx)
			} else if *nativeNetwork {
				if retained != nil {
					e = nil
				} else {
					e = netconfig.WaitMacCleanupNative(cleanupCtx, session.GUID, session.Token, l)
				}
			} else {
				e = runBridgeNetworkScript(cleanupCtx, "cleanup_verify", check, l)
			}
		}
		if cleanupErr != nil || e != nil {
			session.Status = "CLEANUP_REQUIRED"
			runErr = errors.Join(runErr, cleanupErr, e)
			l.Printf("CLEANUP_REQUIRED: %v", runErr)
		} else {
			session.Status = "CLEAN"
			l.Print("OWNED_CLEANUP_VERIFIED")
		}
		if e = record(); e != nil {
			runErr = errors.Join(runErr, e)
		} else if *residentFirewall && session.Status == "CLEAN" {
			// Completed obligations must not strand an older rollback reader on
			// this new journal format. Keep separate resident rule receipts.
			e = bridge.ConsumeResidentOwnedSession(dir, session, func() error {
				absent, e := netconfig.MacAdapterAbsentNative()
				if e != nil {
					return fmt.Errorf("MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN: %w", e)
				}
				if !absent {
					return fmt.Errorf("MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN")
				}
				return nil
			})
			runErr = errors.Join(runErr, e)
		}
	}()
	if *residentFirewall || *ownedDadZero {
		launchPhase = "mac_typed_instance"
		residentInstance, err = netconfig.CaptureOwnedMacNative(tun.Index, tun.LUID, false)
		if err != nil {
			return err
		}
		launchPhase = "mac_attached_owner"
		if err = verifyAttachedSession(ctx); err != nil {
			return err
		}
	}
	freshDadZero := false
	if *ownedDadZero && ownedDadUsable {
		ownedDadIdentity = interfaceconfig.OwnedDADIdentity{Scope: interfaceconfig.Scope{Role: "mac", GUID: tun.GUID.String(), Index: tun.Index, LUID: tun.LUID}, Instance: residentInstance}
		ownedDadPrepared = true // Failure after original capture retains its obligation.
		launchPhase = "mac_dad_apply"
		o, e := interfaceconfig.ApplyOwnedDADZero(ctx, configDir, ownedDadIdentity, func() error { return verifyAttachedSession(ctx) })
		l.Printf("USB_MAC_OWNED_DAD duration_ms=%d applied=%t verified=%t", o.DurationMS, o.Applied, o.Verified)
		if e != nil || !o.Verified {
			// The optimization's ledger/write/readback is not a connection gate.
			// Actual lease, USB and typed interface drift still fails closed.
			l.Print("USB_MAC_OWNED_DAD_FALLBACK_PREFERRED_WAIT")
			if ownerErr := verifyAttachedSession(ctx); ownerErr != nil {
				return errors.Join(e, ownerErr)
			}
		} else {
			freshDadZero = true
		}
	}
	if freshDadZero && !*residentFirewall {
		setup, err = netconfig.UseFreshDADZeroMacWait(setup, tun.Index, *sharedHost)
		if err != nil {
			return err
		}
	}
	if *residentFirewall {
		p := usbaddress.InterfaceProof{Index: tun.Index, LUID: tun.LUID, GUID: tun.GUID.String()}
		owner := func() error {
			if e := verifyAttachedSession(ctx); e != nil {
				return e
			}
			return verifyCoreOwner()
		}
		launchPhase = "mac_source_begin"
		if e := coreSource.Complete(); e != nil {
			return e
		}
		launchPhase = "mac_resident_mac_plan"
		macPlan, e := netconfig.PrepareResidentMacFirewall(ctx, configDir, p, owner)
		if e != nil {
			// Preserve the actual first cause before an optional, once-per-child
			// read-only probe. Its output never changes the failed Ready result.
			reportFirstFailure(e)
			diagnosticScript := ""
			switch netconfig.ResidentFirewallErrorDetails(e).Code {
			case "USB_NATIVE_FIREWALL_CONSTRAINT_NULL":
				diagnosticScript = netconfig.ResidentMacNullProjectionScript()
			case "USB_RESIDENT_FOREIGN_SCOPE":
				diagnosticScript = netconfig.ResidentMacAnchorProjectionScript()
			}
			if diagnosticScript != "" && owner() == nil {
				diagnosticCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
				_ = runBridgeNetworkScript(diagnosticCtx, "diagnostic", diagnosticScript, l)
				cancel()
			}
			return e
		}
		launchPhase = "mac_resident_core_plan"
		corePlan, e := netconfig.PrepareResidentCoreFirewall(ctx, configDir, p, "10.6.9.2", *coreExecutable, owner, connectioninstall.VerifyCoreExecutable)
		if e != nil {
			return e
		}
		launchPhase = "mac_resident_network_plan"
		network, e := netconfig.ResidentVirtualHostMacScript(tun.Index, tun.GUID.String(), mtu, topology, freshDadZero)
		if e != nil {
			return e
		}
		launchPhase = "mac_resident_batch_owner"
		if e = owner(); e != nil {
			return e
		}
		launchPhase = "mac_resident_batch"
		batchErr := netconfig.CompleteResidentPermissionBatch(ctx, network, []netconfig.ResidentPermissionPlan{macPlan, corePlan}, func(runCtx context.Context, script string) error {
			return runBridgeNetworkScript(runCtx, "setup", script, l)
		})
		reportFirstFailure(batchErr)
		launchPhase = "mac_source_complete"
		if e = errors.Join(batchErr, coreSource.Complete()); e != nil {
			return e
		}
	} else if *nativeNetwork {
		p := usbaddress.InterfaceProof{Index: tun.Index, GUID: tun.GUID.String(), LUID: tun.LUID}
		var beforeAddress func(usbaddress.InterfaceProof) error
		if *dadZero {
			dadScope = interfaceconfig.Scope{Role: "mac", GUID: p.GUID, Index: p.Index, LUID: p.LUID}
			beforeAddress = func(current usbaddress.InterfaceProof) error {
				if current != p {
					return fmt.Errorf("USB_MAC_DAD_SCOPE_CHANGED")
				}
				owner := func() error {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if retained != nil {
						return retained.VerifyOwnedNativeLease(ctx, p)
					}
					if !tun.FactoryHandleHeld() {
						return fmt.Errorf("USB_MAC_DAD_FACTORY_REQUIRED")
					}
					nodes, e := winusb.Enumerate(l)
					if e != nil {
						return e
					}
					cp, dp, e := winusb.Pair(nodes, 0, false)
					if e != nil || cp != initialControl || dp != initialData || !device.MatchesOpenedPair(cp, dp) {
						return fmt.Errorf("USB_MAC_DAD_USB_ATTACHMENT_CHANGED")
					}
					return netconfig.VerifyOwnedWintunRecoveryIdentityNative(ctx, netconfig.OwnedProfileRecoveryIdentity{Role: "mac", GUID: p.GUID, Index: p.Index, LUID: p.LUID}, func() error {
						if !tun.FactoryHandleHeld() || tun.Index != p.Index || tun.LUID != p.LUID {
							return fmt.Errorf("USB_MAC_DAD_FACTORY_LEASE_CHANGED")
						}
						return nil
					})
				}
				observation, e := interfaceconfig.ApplyDADZero(ctx, configDir, dadScope, owner)
				// Any failed mutation keeps its protected original and is handled by the
				// same cleanup path; Applied alone is never readiness.
				dadApplied = true
				l.Printf("USB_MAC_DAD duration_ms=%d applied=%t verified=%t", observation.DurationMS, observation.Applied, observation.Verified)
				return e
			}
		}
		if retained != nil {
			err = netconfig.SetupMacNetworkRetainedNative(ctx, p, mtu, session.Token, *profile, *sharedHost, topology, beforeAddress, func(p usbaddress.InterfaceProof) error { return retained.VerifyAddress(ctx, p) }, l)
		} else {
			err = netconfig.SetupMacNetworkNative(ctx, p, mtu, session.Token, *profile, *sharedHost, topology, beforeAddress, l)
		}
		if err != nil {
			return err
		}
		if *persistentConfig && retained == nil {
			scope := interfaceconfig.Scope{Role: "mac", GUID: p.GUID, Index: p.Index, LUID: p.LUID}
			owner := func() error {
				if e := usbOwner(scope); e != nil {
					return e
				}
				if !tun.FactoryHandleHeld() || tun.Index != scope.Index || tun.LUID != scope.LUID {
					return fmt.Errorf("USB_MAC_PERSISTENT_FACTORY_LEASE_CHANGED")
				}
				return netconfig.VerifyOwnedWintunRecoveryIdentityNative(ctx, netconfig.OwnedProfileRecoveryIdentity{Role: "mac", GUID: scope.GUID, Index: scope.Index, LUID: scope.LUID}, func() error {
					if !tun.FactoryHandleHeld() {
						return fmt.Errorf("USB_MAC_PERSISTENT_FACTORY_LEASE_CHANGED")
					}
					return nil
				})
			}
			created, e := macOwnedAddressCreated(p)
			if e != nil {
				return e
			}
			retained, e = interfaceconfig.CapturePersistentSecondaryAfterAddress(ctx, configDir, scope, owner, interfaceconfig.WintunProfileOps(scope, owner, l), created)
			if e != nil {
				return e
			}
			if e = retained.BindFactoryDevice(ctx, tun); e != nil {
				return e
			}
			if e = interfaceconfig.CaptureSecondaryFactoryBinding(ctx, retained); e != nil {
				return e
			}
		}
		if retained != nil {
			session.Version = bridge.RetainedSessionVersion
			session.Retained = &bridge.RetainedAddress{Index: tun.Index, LUID: tun.LUID, Created: retained.Created(), Mode: retained.AddressMode(), ReceiptSHA256: retained.ReceiptSHA256(), Prepared: true}
			if err = record(); err != nil {
				return err
			}
		}

	} else if err := runBridgeNetworkScript(ctx, "setup", setup, l); err != nil {
		return err
	}
	launchPhase = "mac_transport_start"
	releaseTopology()
	prefix := 24
	if *profile == usbaddress.Unified {
		prefix = 32
	}
	l.Printf("WINTUN_CONFIGURED IP=%s/%d MTU=%d no gateway/DNS", addresses.Windows, prefix, mtu)
	server, err := bench.StartForProfile(ctx, l, *profile)
	if err != nil {
		return err
	}
	defer server.Close()
	var reads []*winusb.Read
	defer func() { device.Data.CloseReads(reads); l.Print("pending reads cancelled and drained") }()
	for j := 0; j < *readDepth; j++ {
		r, e := winusb.NewRead(device.ReadSize)
		if e != nil {
			return e
		}
		reads = append(reads, r)
		if e = device.Data.Submit(r, device.In.ID); e != nil {
			return e
		}
	}
	memorydiag.RecordStage("usb_in_buffers_allocated_and_submitted")
	ctx, cancelIO := context.WithCancel(ctx)
	var workers sync.WaitGroup
	waitIO, e := usbwait.NewMode(ctx, bench.ReadEventWaitMode, bench.ObserveEventWaitMode)
	if e != nil {
		cancelIO()
		return e
	}
	defer waitIO.Close()
	waitTun, e := usbwait.NewMode(ctx, bench.ReadEventWaitMode, bench.ObserveEventWaitMode)
	if e != nil {
		cancelIO()
		return e
	}
	defer waitTun.Close()
	bench.SetWaitDiagnostics(func() any {
		return map[string]any{"usb_in": waitIO.Diagnostics(), "wintun_receive": waitTun.Diagnostics()}
	})
	defer bench.SetWaitDiagnostics(nil)
	defer workers.Wait()
	defer cancelIO()
	buffers := packetbuffer.New()
	buffers.Enabled = bench.ReuseBuffers
	bench.SetBufferTrim(buffers.Trim)
	defer bench.SetBufferTrim(nil)
	var rawReceiver atomic.Pointer[rawusb.Receiver]
	internet := newInternetPolicy(ctx, *internetRoot)
	var publishedPeer atomic.Value
	publishedPeer.Store(bridge.Peer{MTU: mtu, Internet: internet.allow, OnInternet: internet.packet})
	errorsCh := make(chan error, 2)
	fromUSB := make(chan ncm.Block, 64)
	// Bound queued data to 512 KiB at the proven 16000-byte maximum.
	// Blocking ingress preserves FIFO/backpressure without dropping packets.
	fromTun := make(chan []byte, 32)
	fail := func(e error) {
		if ctx.Err() != nil {
			return
		}
		select {
		case errorsCh <- e:
		default:
		}
		// Release ingress if a failed OUT owner leaves a full control queue.
		cancelIO()
	}
	workers.Add(2)
	go func() {
		defer workers.Done()
		pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels("worker", "usb-in")))
		stream := ncm.Stream{}
		defer stream.Close()
		for cursor := 0; ctx.Err() == nil; cursor = (cursor + 1) % len(reads) {
			r := reads[cursor]
			// Preserve submission/FIFO order, but collect an already completed
			// request directly. Waiting on its event first doubles hot-path calls.
			var b []byte
			var e error
			for ctx.Err() == nil {
				b, e = device.Data.Result(r, false)
				if !errors.Is(e, windows.ERROR_IO_INCOMPLETE) {
					break
				}
				if _, e = waitIO.Current(r.Overlapped.HEvent); e != nil {
					fail(e)
					return
				}
			}
			if ctx.Err() != nil {
				return
			}
			if e != nil {
				fail(fmt.Errorf("Bulk IN: %w", e))
				return
			}
			if bench.ReuseBuffers() {
				stream.Pool = buffers
			} else {
				stream.Pool = nil
			}
			raw := rawReceiver.Load()
			if raw != nil {
				raw.Counter.Read(len(b))
			}
			usbReceivedAt := time.Now()
			blocks, e := stream.Feed(b)
			if e != nil {
				fail(fmt.Errorf("NTB decode: %w", e))
				return
			}
			for _, block := range blocks {
				latencyprobe.MarkFrames(block.Frames, publishedPeer.Load().(bridge.Peer), true, "usb", usbReceivedAt)
			}
			if e = device.Data.Submit(r, device.In.ID); e != nil {
				for _, block := range blocks {
					block.Release()
				}
				fail(e)
				return
			}
			if raw != nil {
				for i := range blocks {
					frames := blocks[i].Frames[:0]
					for _, frame := range blocks[i].Frames {
						if !raw.Consume(frame) {
							frames = append(frames, frame)
						}
					}
					blocks[i].Frames = frames
				}
			}
			for i, block := range blocks {
				if len(block.Frames) == 0 {
					block.Release()
					continue
				}
				select {
				case fromUSB <- block:
				case <-ctx.Done():
					for _, unsent := range blocks[i:] {
						unsent.Release()
					}
					return
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels("worker", "wintun-receive")))
		for ctx.Err() == nil {
			var allocate func(int) []byte
			if bench.ReuseBuffers() {
				allocate = buffers.Get
			}
			b, e := tun.ReceiveWithBuffer(allocate)
			if errors.Is(e, windows.ERROR_NO_MORE_ITEMS) {
				if _, e = waitTun.Current(tun.ReadEvent()); e != nil {
					fail(e)
					return
				}
				continue
			}
			if e != nil {
				fail(fmt.Errorf("Wintun receive: %w", e))
				return
			}
			latencyprobe.Mark(b, false, "receive", time.Now())
			select {
			case fromTun <- b:
			case <-ctx.Done():
				buffers.Put(b)
				return
			}
		}
	}()
	l.Printf("%d overlapped bulk reads submitted; Wintun session and bounded TCP benchmark listening", *readDepth)
	peer := bridge.Peer{MTU: mtu, Internet: internet.allow, OnInternet: internet.packet}
	dhcp := macdhcp.Server{Local: ncm.WindowsIP, Peer: ncm.MacIP, Internet: internet.enabled}
	if *profile == usbaddress.Unified {
		l.Print("MAC_DHCP_STARTED no_router=true no_dns=true usb_only=true")
	}
	var stats statistics
	var sequence uint16
	var encoded []byte
	peerReady := make(chan struct{})
	controls := make(chan [][]byte, 64)
	batchMax, err := ncm.BatchLimit(device.Parameters, mtu+14, *batchRequested)
	if err != nil {
		return err
	}
	batchSizes, err := ncm.NewBatchSizes(device.Parameters, *batchRequested, int(device.MaxSegment))
	if err != nil {
		return err
	}
	writer, err := winusb.NewWriter(device.Data, device.Out.ID, int(min(device.Parameters.OutMax, ncm.MaxNTB)), *txDepth)
	if err != nil {
		return err
	}
	// Join all workers before cancelling/draining pinned writer buffers.
	defer func() {
		cancelIO()
		workers.Wait()
		for len(fromUSB) > 0 {
			block := <-fromUSB
			block.Release()
		}
		for len(fromTun) > 0 {
			buffers.Put(<-fromTun)
		}
		writer.Close()
	}()
	l.Printf("TRANSPORT tx_depth=%d batch_max=%d read_depth=%d max_ntb=%d no_batch_timer=true independent_out=true", *txDepth, batchMax, *readDepth, device.Parameters.OutMax)
	type txSnapshot struct {
		counts                                                  bridge.TXCounters
		submitted, completed, bytes, waitNanos, completionNanos uint64
		maxPending                                              int
	}
	var txMu sync.Mutex
	var tx txSnapshot
	snapshotTX := func() txSnapshot { txMu.Lock(); defer txMu.Unlock(); return tx }
	publishTX := func(counts bridge.TXCounters) {
		value := txSnapshot{counts: counts, submitted: writer.Submitted, completed: writer.Completed, bytes: writer.Bytes, waitNanos: writer.WaitNanos, completionNanos: writer.MaxCompletionNanos, maxPending: writer.MaxPending}
		txMu.Lock()
		tx = value
		txMu.Unlock()
	}
	combinedStats := func() statistics {
		value := stats
		out := snapshotTX()
		value.USBWrites = out.completed
		value.ToMac = out.counts.Packets
		value.ToMacBytes = out.counts.Bytes
		value.ToMacProfile = out.counts.Profile
		value.MTUExceeded = out.counts.MTUExceeded
		value.MTUExceededBytes = out.counts.MTUExceededBytes
		value.MaxRejectedIPLength = out.counts.MaxRejectedIPLength
		value.Filtered += out.counts.Filtered
		value.PendingOverflow += out.counts.PendingOverflow
		value.Dropped += out.counts.Filtered + out.counts.PendingOverflow
		return value
	}
	rawWork := make(chan func() error, 1)
	bench.SetLatencyRunner(func(_ context.Context, kind string, seconds int, id, key string) (any, error) {
		if kind != "RESULT" && kind != "STOP" && rawReceiver.Load() != nil {
			return nil, fmt.Errorf("raw capture already active")
		}
		switch kind {
		case "RESULT":
			return latencyprobe.Result(id)
		case "STOP":
			if e := latencyprobe.Stop(id); e != nil {
				return nil, e
			}
		default:
			if e := latencyprobe.Start(ctx, kind, seconds, id, key); e != nil {
				return nil, e
			}
		}
		return map[string]any{"status": "complete", "mode": kind, "id": id}, nil
	})
	memorydiag.RecordStage("usb_out_pool_allocated")
	if e = writer.EnableCompletionObservation(ctx, func(b []byte) func(time.Time) {
		if !latencyprobe.Running() {
			return nil
		}
		block, err := ncm.Decode(b)
		if err != nil {
			return nil
		}
		return latencyprobe.CompletionMarker(block.Frames, publishedPeer.Load().(bridge.Peer))
	}); e != nil {
		return e
	}
	writer.DiagnosticSubmit = func(b []byte, at time.Time) {
		if latencyprobe.Running() {
			block, e := ncm.Decode(b)
			if e == nil {
				latencyprobe.MarkFrames(block.Frames, publishedPeer.Load().(bridge.Peer), false, "submit", at)
			}
		}
	}
	writer.DiagnosticComplete = func(b []byte, at time.Time) {
		if latencyprobe.Running() {
			block, e := ncm.Decode(b)
			if e == nil {
				latencyprobe.MarkFrames(block.Frames, publishedPeer.Load().(bridge.Peer), false, "complete", at)
			}
		}
	}

	bench.SetRawRunner(rawRunner(ctx, &rawReceiver, rawWork, func() bridge.Peer { return publishedPeer.Load().(bridge.Peer) }, writer, device.Parameters, &encoded, &sequence))
	defer bench.SetRawRunner(nil)
	workers.Add(1)
	go func() {
		defer workers.Done()
		pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels("worker", "usb-out")))
		transmitter := bridge.Transmitter{
			// The writer consumes/copies before returning, so frame/packet reuse
			// cannot race pinned USB requests. Baseline mode retains old ownership.
			ReuseFramesNow: bench.ReuseBuffers, ReleasePacket: buffers.Put,
			Packets: fromTun, Controls: controls, PeerReady: peerReady, Batch: batchMax, Work: rawWork,
			Peer: func() bridge.Peer { return publishedPeer.Load().(bridge.Peer) },
			Write: func(frames [][]byte) error {
				for len(frames) > 0 {
					n, e := batchSizes.Limit(frames)
					if e != nil {
						return e
					}
					block, e := ncm.EncodeInto(encoded, frames[:n], sequence, device.Parameters)
					if e != nil {
						return e
					}
					encoded = block
					sequence++
					if e = writer.Submit(ctx, block); e != nil {
						return e
					}
					frames = frames[n:]
				}
				return nil
			},
			Pending: func() bool { return !bench.EventWaits() || writer.Pending() > 0 },
			Poll:    func() error { return writer.Poll(ctx) }, Changed: publishTX,
		}
		if e := transmitter.Run(ctx); e != nil && ctx.Err() == nil {
			fail(e)
		}
	}()
	send := func(frames [][]byte) error { return bridge.EnqueueControl(ctx, controls, frames) }
	memorydiag.RecordStage("bridge_workers_started")
	arpTimer := time.NewTicker(time.Second)
	defer arpTimer.Stop()
	statsTimer := time.NewTicker(5 * time.Second)
	defer statsTimer.Stop()
	var diagnosticNonce string
	var snapshot []byte
	var snapshotAt time.Time
	var peerAnnounced bool
	var trial *mtutrial.Trial
	trialFinished := false
	refreshPath := func(mtu int) {
		macProof := usbaddress.InterfaceProof{Index: tun.Index, LUID: tun.LUID, GUID: tun.GUID.String()}
		err := netconfig.RefreshMacPathCache(ctx, macProof, topology, mtu, l)
		if err != nil {
			l.Printf("USB_MAC_PATH_CACHE_REFRESH_FAILED error=%v; verified link retained", err)
		}
		// This bounded marker reaches the parent status and UI. A cache failure
		// keeps the connection available but cannot silently claim healthy MTU.
		l.Printf("USB_MAC_PATH_STATE mtu=%d healthy=%t", mtu, err == nil)
	}
	finishTrial := func() error {
		if trial == nil || !trial.Done || trialFinished {
			return nil
		}
		trialFinished = true
		if trial.Proven == 1500 {
			refreshPath(1500)
			l.Print("MTU_TRIAL_RESULT effective_mtu=1500 jumbo_roundtrip=false; baseline preserved")
			return nil
		}
		e := netconfig.SetVerifiedMacMTUNative(ctx, tun.Index, tun.GUID.String(), tun.LUID, trial.Proven)
		if e != nil {
			re := netconfig.SetVerifiedMacMTUNative(ctx, tun.Index, tun.GUID.String(), tun.LUID, 1500)
			if re != nil {
				return fmt.Errorf("MTU_ROLLBACK_FAILED: %v; original update: %w", re, e)
			}
			l.Printf("MTU_TRIAL_RESULT effective_mtu=1500 update_error=%v rollback_verified=true", e)
			refreshPath(1500)
			return nil
		}
		peer.MTU = trial.Proven
		publishedPeer.Store(peer)
		// Publish the proven frame limit before invalidating cached paths: a
		// new full-size packet must not race the old 1500-byte bridge filter.
		refreshPath(trial.Proven)
		l.Printf("MTU_TRIAL_RESULT effective_mtu=%d jumbo_roundtrip=true Windows_readback=true", peer.MTU)
		return nil
	}
	if err = send([][]byte{bridge.ARPRequest()}); err != nil {
		return err
	}
	l.Print(probecontrol.ReadyMarker)
	for {
		select {
		case <-ctx.Done():
			out := snapshotTX()
			l.Printf("SUMMARY stats=%+v tx_submitted=%d tx_completed=%d", combinedStats(), out.submitted, out.completed)
			select {
			case e := <-errorsCh:
				return e
			default:
				return nil
			}
		case err = <-errorsCh:
			return err
		case <-statsTimer.C:
			reportInterfaceOperations()
			out := snapshotTX()
			l.Printf("STATS %+v peer=%s", combinedStats(), net.HardwareAddr(peer.MAC[:]))
			l.Printf("TX_STATS submitted=%d completed=%d bytes=%d max_pending=%d backpressure_ms=%.3f completion_observed_max_ms=%.3f tun_queue=%d usb_queue=%d control_queue=%d independent_out=true", out.submitted, out.completed, out.bytes, out.maxPending, float64(out.waitNanos)/1e6, float64(out.completionNanos)/1e6, len(fromTun), len(fromUSB), len(controls))
		case now := <-arpTimer.C:
			if trial != nil {
				if frame := trial.Tick(now); frame != nil {
					if err = send([][]byte{frame}); err != nil {
						return err
					}
				}
				if err = finishTrial(); err != nil {
					return err
				}
			}
			if peer.MAC == [6]byte{} {
				if err = send([][]byte{bridge.ARPRequest()}); err != nil {
					return err
				}
			}
		case block := <-fromUSB:
			if e := func() error {
				defer block.Release()
				stats.USBReads++
				for _, frame := range block.Frames {
					if *profile == usbaddress.Unified {
						priorACKs := dhcp.ACKs
						reply, consumed, failure := dhcp.Handle(frame, peer.MAC, time.Now())
						if dhcp.ACKs > priorACKs {
							internet.ack()
						}
						if failure != "" {
							return fmt.Errorf("%s", failure)
						}
						if consumed {
							if err = send([][]byte{reply}); err != nil {
								return err
							}
							l.Printf("MAC_DHCP_COUNTERS discoveries=%d offers=%d acks=%d", dhcp.Discoveries, dhcp.Offers, dhcp.ACKs)
							continue
						}
						// After DHCP fixes a client identity, another Ethernet sender
						// cannot acquire the bridge's fixed lease by using its IPv4.
						if dhcp.MAC != [6]byte{} {
							e, er := ncm.ParseEthernet(frame)
							if er != nil || e.Source != dhcp.MAC {
								stats.Dropped++
								stats.Filtered++
								continue
							}
						}
					}
					if trial != nil {
						proven, consumed := trial.Accept(frame)
						if proven > 0 {
							l.Printf("MTU_TRIAL_PROVEN mtu=%d replies=2 unfragmented=true", proven)
						}
						if consumed {
							if err = finishTrial(); err != nil {
								return err
							}
							continue
						}
					}
					arp, ip := peer.FromMac(frame)
					if arp != nil {
						if err = send([][]byte{arp}); err != nil {
							return err
						}
						l.Print("ARP_REPLY_SENT")
					}
					if ip != nil {
						if reply, consumed := latencyprobe.Receive(ip); consumed {
							if reply != nil {
								frame, e := peer.FromWindows(reply)
								if e != nil {
									return e
								}
								if e = send([][]byte{frame}); e != nil {
									return e
								}
							}
							continue
						}
						if nonce, mac, ok := ncm.DiagnosticRequest(frame); ok && mac == peer.MAC {
							// Same-nonce retransmissions are immutable; a new nonce gets fresh logs.
							if nonce != diagnosticNonce {
								if time.Since(snapshotAt) < time.Second {
									continue
								}
								snapshot, err = diagnostics(dir, nonce, combinedStats(), topology)
								if err != nil {
									return err
								}
								diagnosticNonce = nonce
								snapshotAt = time.Now()
							}
							frames, e := ncm.DiagnosticFrames(snapshot, nonce, mac)
							if e != nil {
								return e
							}
							for _, f := range frames {
								if err = send([][]byte{f}); err != nil {
									return err
								}
							}
							l.Printf("DIAGNOSTICS_SENT nonce=%s chunks=%d bytes=%d", nonce, len(frames), len(snapshot))
							continue
						}
						if err = tun.Send(ip); err != nil {
							if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
								stats.Dropped++
								stats.RingOverflow++
								continue
							}
							return fmt.Errorf("Wintun send: %w", err)
						}
						latencyprobe.Mark(ip, true, "inject", time.Now())
						stats.ToWindows++
						stats.ToWindowsBytes += uint64(len(ip))
						stats.ToWindowsProfile.Observe(ip)
					} else if arp == nil {
						stats.Dropped++
						stats.Filtered++
					}
				}
				if peer.MAC != [6]byte{} && !peerAnnounced {
					peerAnnounced = true
					if *profile == usbaddress.Unified && device.Datagram != nil {
						var nonce [16]byte
						if _, err = rand.Read(nonce[:]); err != nil {
							return err
						}
						trial = mtutrial.New(peer.MAC, nonce, min(int(device.Datagram.Current), batchSizes.FrameLimit))
						l.Printf("MTU_TRIAL_STARTED baseline=1500 frame_limit=%d peer=%s no_peer_install=true", device.Datagram.Current, net.HardwareAddr(peer.MAC[:]))
					}
					l.Printf("PEER_RESOLVED mac=%s IPv4=%s", net.HardwareAddr(peer.MAC[:]), addresses.Peer)
					publishedPeer.Store(peer)
					close(peerReady)
					// This invokes the real Windows ping executable bound to Wintun's address.
					workers.Add(1)
					go func() {
						defer workers.Done()
						pingCtx, done := context.WithTimeout(ctx, 12*time.Second)
						defer done()
						if *nativeNetwork {
							e := netconfig.ProbeWindowsICMPNative(pingCtx, addresses.Windows, addresses.Peer, l)
							l.Printf("WINDOWS_OS_ICMP_NATIVE completed=%t", e == nil)
						} else {
							cmd := exec.CommandContext(pingCtx, filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"), "-4", "-S", addresses.Windows, "-n", "5", "-w", "1000", addresses.Peer)
							cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
							output, e := cmd.CombinedOutput()
							l.Printf("WINDOWS_OS_PING exit=%v output=%s", e, output)
						}
						if ctx.Err() == nil && !*residentFirewall {
							var e error
							if *nativeNetwork {
								e = netconfig.SetPrivateMacProfileNative(ctx, usbaddress.InterfaceProof{Index: tun.Index, GUID: tun.GUID.String(), LUID: tun.LUID}, l)
							} else {
								e = runBridgeNetworkScript(ctx, "private_profile", netconfig.PrivateProfileScript(tun.Index, tun.GUID.String()), l)
							}
							if e != nil {
								l.Printf("owned private profile warning=%v; scoped rules remain active", e)
							}
						}
					}()
				}

				return nil
			}(); e != nil {
				return e
			}

		}
	}
}

func Main() {
	exe, e := os.Executable()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	dir := filepath.Dir(exe)
	f, e := logfile.Open(filepath.Join(dir, "usbnet-bridge.log"), 8*1024*1024)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	l := log.New(io.MultiWriter(os.Stdout, f), "", log.Ldate|log.Ltime|log.Lmicroseconds)
	l.Printf("version=%s", version)
	e = run(dir, l)
	if e != nil {
		if message, ok := netconfig.NativeStepFailureMessage(e); ok {
			l.Printf("%s%s", netconfig.NativeFailurePrefix, message)
		}
		l.Printf("RESULT=STOP error=%v", e)
	} else {
		l.Print("RESULT=STOPPED_GRACEFULLY; hardware acceptance requires Mac evidence")
	}
	f.Close()
	if e != nil {
		os.Exit(1)
	}
}
