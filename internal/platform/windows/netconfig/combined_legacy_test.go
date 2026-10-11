package netconfig

import (
	"context"
	"errors"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestCombinedLegacyBatchRetainsProcessFailureCancellationAndFreshOwners(t *testing.T) {
	for _, scenario := range []string{"success", "pre-owner-changed", "post-owner-changed", "first-fragment-failed", "cancel-before", "cancel-by-pre-owner", "cancel-in-process"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ownerCalls, processCalls := 0, 0
			firstError := errors.New("actual first fragment failed")
			ownerError := errors.New("actual source/interface/session changed")
			owner := func() error {
				ownerCalls++
				if scenario == "pre-owner-changed" || (scenario == "post-owner-changed" && ownerCalls == 2) {
					return ownerError
				}
				if scenario == "cancel-by-pre-owner" {
					cancel()
				}
				return nil
			}
			if scenario == "cancel-before" {
				cancel()
			}
			err := ExecuteCombinedLegacyNetwork(ctx, "original ordered fragments", owner, func(c context.Context, script string) error {
				processCalls++
				if c != ctx || script != "original ordered fragments" {
					t.Fatal("process lost exact original context/script")
				}
				if scenario == "first-fragment-failed" {
					return firstError
				}
				if scenario == "cancel-in-process" {
					cancel()
				}
				return nil
			})
			switch scenario {
			case "success":
				if err != nil || ownerCalls != 2 || processCalls != 1 {
					t.Fatal("successful same-stage batch must have two fresh owner reads and one process", err, ownerCalls, processCalls)
				}
			case "pre-owner-changed":
				if !errors.Is(err, ownerError) || processCalls != 0 {
					t.Fatal("unowned first fragment executed", err, processCalls)
				}
			case "post-owner-changed":
				if !errors.Is(err, ownerError) || ownerCalls != 2 || processCalls != 1 {
					t.Fatal("successful process hid changed final owner", err, ownerCalls, processCalls)
				}
			case "first-fragment-failed":
				if !errors.Is(err, firstError) || ownerCalls != 1 || processCalls != 1 {
					t.Fatal("later completion swallowed first process failure", err, ownerCalls, processCalls)
				}
			default:
				if !errors.Is(err, context.Canceled) || (scenario != "cancel-in-process" && processCalls != 0) || (scenario == "cancel-in-process" && ownerCalls != 1) {
					t.Fatal("cancelled connection admitted by successful script", err, ownerCalls, processCalls)
				}
			}
		})
	}
}

func TestCombinedLegacyMacServicesPreserveExactScopedFragmentsAndReadback(t *testing.T) {
	resetCoreBaselineFixture(t)
	guid, token := "{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567"
	script, err := LegacyMacServiceScript(guid, token, `C:\USB-Link.exe`)
	if err != nil {
		t.Fatal(err)
	}
	files, err := FileReceiverRuleForProfile(guid, token, true, "unified")
	if err != nil {
		t.Fatal(err)
	}
	coreBaselines.Lock()
	p := coreBaselines.pending[len(coreBaselines.pending)-1]
	coreBaselines.Unlock()
	if script != files+"\n"+p.script || len(p.rules) != 2 {
		t.Fatal("original ordered fragment or exact core suffix changed")
	}
	if p.rules[0].Program != `C:\USB-Link.exe` || p.rules[0].Local != "10.6.9.1" || p.rules[0].Peer != "10.6.9.2" || p.rules[1].Program != "System" || p.rules[1].Service != "LanmanServer" || p.rules[1].Ports != "445" {
		t.Fatal("program/peer/SMB scope changed", p.rules)
	}
	if !strings.Contains(files, "Suhang-USB-Phase2-"+token+"-FILES") || !strings.Contains(files, "Get-NetFirewallRule -ErrorAction Stop") || !strings.Contains(files, "-RemoteAddress '10.6.9.2'") || strings.Contains(script, "SetIpInterfaceEntry") {
		t.Fatal("legacy precise token cleanup or peer scope lost")
	}
	output := "OWNED_FIREWALL_CLEANUP_VERIFIED removed=0\n" + fixtureMetadata(p, "CREATED", "COMPLETE", strings.Repeat("c", 64)) + "\nSUHANG_NETWORK_SCRIPT_OK"
	clean, err := CompleteCorePermissionReadback(script, output, func(v string) bool {
		return strings.HasSuffix(v, "USB_CORE_PERMISSION_READY\nSUHANG_NETWORK_SCRIPT_OK")
	})
	if err != nil || !strings.HasSuffix(clean, "USB_CORE_PERMISSION_READY\nSUHANG_NETWORK_SCRIPT_OK") {
		t.Fatal("exact combined completed readback rejected", clean, err)
	}
	if _, err := CompleteCorePermissionReadback(script, output, func(string) bool { return true }); err == nil {
		t.Fatal("completed transcript reused")
	}
}

func TestCombinedLegacyMacPartialOrUnownedCompletionNeverAdmitsCore(t *testing.T) {
	for _, failure := range []string{"partial-metadata", "missing-final-ready", "failed-process", "unrelated-script"} {
		t.Run(failure, func(t *testing.T) {
			resetCoreBaselineFixture(t)
			script, err := LegacyMacServiceScript("{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567", `C:\USB-Link.exe`)
			if err != nil {
				t.Fatal(err)
			}
			coreBaselines.Lock()
			p := coreBaselines.pending[len(coreBaselines.pending)-1]
			coreBaselines.Unlock()
			output := fixtureMetadata(p, "CREATED", "COMPLETE", strings.Repeat("d", 64))
			ready := true
			switch failure {
			case "partial-metadata":
				output = strings.Join(strings.Split(output, "\n")[1:], "\n")
			case "missing-final-ready":
				output = strings.TrimSuffix(output, "\nUSB_CORE_PERMISSION_READY")
			case "failed-process":
				ready = false
			case "unrelated-script":
				script = "# " + p.nonce
			}
			if _, err := CompleteCorePermissionReadback(script, output, func(string) bool { return ready }); err == nil || CorePermissionReadbackStats().CacheEntries != 0 {
				t.Fatal("incomplete execution established trusted baseline", err)
			}
		})
	}
	for _, args := range [][3]string{{"bad", "0123456789abcdef01234567", `C:\USB-Link.exe`}, {usbaddress.HostGUID, "bad", `C:\USB-Link.exe`}, {"{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567", "relative.exe"}} {
		if _, err := LegacyMacServiceScript(args[0], args[1], args[2]); err == nil {
			t.Fatal("invalid original script plan accepted")
		}
	}
}

func TestCombinedLegacyLaunchIndependentAndDefaultDisabled(t *testing.T) {
	if CombinedLegacyNetworkEnabled() {
		t.Fatal("combined mode must default off")
	}
	defer SetCombinedLegacyNetworkEnabled(false)
	SetCombinedLegacyNetworkEnabled(true)
	if !CombinedLegacyNetworkEnabled() {
		t.Fatal("selection lost")
	}
	base := "mac-runtime-" + strings.Repeat("a", 64)
	event := `Local\USBLinkGatewayReady-` + strings.Repeat("a", 24)
	if err := ValidateCombinedLegacyMacLaunch(true, false, false, true, true, "unified", event, base); err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][4]bool{{true, false, true, true}, {false, true, true, true}, {false, false, false, true}, {false, false, true, false}} {
		if ValidateCombinedLegacyMacLaunch(true, flags[0], flags[1], flags[2], flags[3], "unified", event, base) == nil {
			t.Fatal("unexpected permission/experiment launch shape accepted", flags)
		}
	}
	if ValidateCombinedLegacyMacLaunch(true, false, false, true, true, "legacy", event, base) == nil || ValidateCombinedLegacyMacLaunch(true, false, false, true, true, "unified", "bad", base) == nil {
		t.Fatal("unprotected/nonshared launch admitted")
	}
}

func TestLegacyRoleTimingCountsActualAttemptsWithoutDynamicLabels(t *testing.T) {
	before := map[string]NativeOperationTiming{}
	for _, row := range NativeOperationTimingsSnapshot() {
		before[row.Operation] = row
	}
	for _, role := range []string{"shared_host", "mac_services", "ipad_permissions", "mac_recovery"} {
		finish := BeginLegacyRoleScriptTiming(role)
		finish(errors.New("not exported private provider error"))
		finish(nil)
	}
	BeginLegacyRoleScriptTiming("arbitrary-path-or-rule")(nil)
	seen := 0
	for _, row := range NativeOperationTimingsSnapshot() {
		if strings.Contains(row.Operation, "arbitrary") {
			t.Fatal("dynamic role leaked")
		}
		if !strings.HasPrefix(row.Operation, "legacy_") || row.Operation == "legacy_network_script" {
			continue
		}
		old := before[row.Operation]
		if row.Count != old.Count+1 || row.Failures != old.Failures+1 || row.InFlight != 0 || row.CumulativeMS < old.CumulativeMS {
			t.Fatal("role invocation counted incorrectly", row)
		}
		seen++
	}
	if seen != 4 {
		t.Fatal("missing fixed execution roles", seen)
	}
}
