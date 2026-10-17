package ipadncm

import (
	"fmt"
	"go/ast"
	"os"
	"strings"
	"testing"
)

func TestLegacyIsolationMigrationReadbackFailureKeepsRemainingOriginals(t *testing.T) {
	for fail := 0; fail < 4; fail++ {
		nativePortable, nativeService, retired := 0, 0, false
		step := 0
		action := func(counter *int) func() error {
			return func() error {
				*counter++
				current := step
				step++
				if current == fail {
					return fmt.Errorf("independent native readback failed")
				}
				return nil
			}
		}
		e := runLegacyIsolationMigration(action(&nativePortable), action(&nativeService), func() error {
			retired = true
			current := step
			step++
			if current == fail {
				return fmt.Errorf("cleanup persistence failed")
			}
			return nil
		})
		if fail == 0 && (nativeService != 0 || retired) {
			t.Fatal("portable readback failure restored service or retired originals")
		}
		if fail == 1 && retired {
			t.Fatal("service original not read back before retirement")
		}
		if (e != nil) != (fail < 3) {
			t.Fatal(fail, e)
		}
	}
}
func TestSimplifiedDefaultCannotPairOrApplyRetiredPolicy(t *testing.T) {
	for _, item := range []struct{ path, name string }{{"../launcher/main_windows.go", "inspect"}, {"../launcher/main_windows.go", "executeMode"}, {"simplified_network_windows.go", "PrepareSimplifiedIPadNetworkAfterConsent"}} {
		c := unpairedCalls(unpairedSourceFunction(t, item.path, item.name))
		for _, name := range []string{"AuthenticateCurrentUSB", "queryModel", "muxDial", "InspectUnpairedPairMetadata", "BindUnpairedExperimentAfterConsent", "EnsureNetworkOnlyForPhase", "applyNetworkOnlyService", "saveUnpairedProductOwner", "writeNetworkOnlyFile", "Begin", "New", "OpenService", "UpdateConfig", "setPortableDisabled"} {
			if c[name] != 0 {
				t.Fatal(item.name, "default path uses retired isolation/paired API", name)
			}
		}
	}
	fn := unpairedSourceFunction(t, "../launcher/main_windows.go", "inspect")
	first, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || unpairedCalls(first)["applicationConsent"] == 0 {
		t.Fatal("fresh actual consent must precede preparation")
	}
	mode := unpairedCalls(unpairedSourceFunction(t, "../launcher/main_windows.go", "executeMode"))
	if mode["RunSelectedNetworkOnlyAppleControl"] == 0 {
		t.Fatal("default bypassed no-session USB control")
	}
	publicMode := unpairedCalls(unpairedSourceFunction(t, "local_ncm_direct_stub_windows.go", "RunSelectedNetworkOnlyAppleControl"))
	if publicMode["RunNetworkOnlyAppleControl"] == 0 || publicMode["RestoreLocalNCMDirect"] == 0 || publicMode["RestoreLocalNCMDirect"] >= publicMode["RunNetworkOnlyAppleControl"] || publicMode["runWithSelectedControlLease"] != 0 {
		t.Fatal("public selection must recover only and delegate to ordinary mode control")
	}
}
func TestLegacyMigrationCannotTouchGroupingOrCreateNewPolicy(t *testing.T) {
	fn := unpairedSourceFunction(t, "simplified_network_windows.go", "migrateLegacyIPadIsolation")
	c := unpairedCalls(fn)
	for _, name := range []string{"RestoreNetworkOnly", "RestoreUnpairedNetworkOnlyProduct", "RestoreConfiguredGroupings", "RecoverGrouping", "restoreGrouping", "restartGroupingRoot", "EnsureNetworkOnly", "saveUnpairedProductOwner", "applyNetworkOnlyService"} {
		if c[name] != 0 {
			t.Fatal("migration altered grouping or created policy", name)
		}
	}
	if c["migrationComplete"] == 0 || c["migrationComplete"] >= c["readNetworkOnlyReceipt"] || c["restorePortableNodeReceipts"] == 0 || c["restoreLegacyAMDSOriginal"] == 0 {
		t.Fatal("migration marker/original readback contract absent")
	}
	c = unpairedCalls(unpairedSourceFunction(t, "network_only_nodes_windows.go", "restoreOwnedPortableNode"))
	if c["finishPortablePresentRestore"] == 0 || c["restorePortablePhantom"] == 0 {
		t.Fatal("restore lost independent native property readback")
	}
	b, e := os.ReadFile("network_only_nodes_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "CM_Disable_DevNode") {
		t.Fatal("portable migration retains disable implementation")
	}

}
func TestSimplifiedStartupGroupingNeverRestoresOrRestarts(t *testing.T) {
	for _, name := range []string{"InspectPersistentNetworkGrouping", "readOwnedPendingNetworkGrouping"} {
		c := unpairedCalls(unpairedSourceFunction(t, "grouping_persistent_windows.go", name))
		for _, forbidden := range []string{"RecoverGrouping", "restoreGrouping", "restartGroupingRoot", "SetBinaryValue", "MoveFileEx", "Remove", "readNetworkOnlyReceipt", "readOwnedUnpairedProductChoice", "readUnpairedProductOwner"} {
			if c[forbidden] != 0 {
				t.Fatal(name, "startup changes grouping or depends on retired policy", forbidden)
			}
		}
	}
	b, e := os.ReadFile("../launcher/main_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, forbidden := range []string{"ipadncm.RestoreNetworkOnly(", "ipadncm.UnpairedNetworkOnlyStartupProtection(", "ipadncm.RestoreNetworkOnlyPortableNodes(", "ipadncm.InitUnpairedNetworkOnlyProduct(", "ipadncm.RestoreUnpairedNetworkOnlyProduct("} {
		if strings.Contains(s, forbidden) {
			t.Fatal("production main retains old policy", forbidden)
		}
	}
	if !strings.Contains(s, "InitSimplifiedIPadNetwork(recoveryDir)") || !strings.Contains(s, "InspectPersistentNetworkGrouping(recoveryDir)") {
		t.Fatal("simplified startup not bound")
	}
}
func TestSimplifiedAlwaysRetainsGatewayAndSharedAddressGuards(t *testing.T) {
	c := unpairedCalls(unpairedSourceFunction(t, "gateway_windows.go", "attachUSBApplicationGate"))
	if c["RestrictIPadNetworkOnly"] == 0 || c["NetworkOnlyEnabled"] != 0 {
		t.Fatal("gateway sync restriction depends on removed toggle")
	}
	b, e := os.ReadFile("application_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, required := range []string{"APPLICATION_SHARED_HOST_UNAVAILABLE", "APPLICATION_SHARED_HOST_PROOF_CHANGED", "SimplifiedIPadNetworkConfigured()"} {
		if !strings.Contains(s, required) {
			t.Fatal("shared endpoint guard missing", required)
		}
	}
	if strings.Contains(s, "Apple 備份與同步暫停") {
		t.Fatal("restored AMDS advertised as stopped")
	}
}
func TestSimplifiedRetiredEntryPointsCannotMutate(t *testing.T) {
	for _, name := range []string{"InitNetworkOnly", "RequestNetworkOnly", "RunPendingNetworkOnly", "EnsureNetworkOnly", "EnsureNetworkOnlyForPhase", "applyNetworkOnlyService", "RestoreNetworkOnlyPortableNodes", "RestoreNetworkOnly"} {
		c := unpairedCalls(unpairedSourceFunction(t, "network_only_windows.go", name))
		for _, write := range []string{"UpdateConfig", "Control", "setPortableDisabled", "saveNetworkOnlyReceipt", "writeNetworkOnlyFile", "RecoverGrouping", "restoreGrouping"} {
			if c[write] != 0 {
				t.Fatal("retired entry still mutates", name, write)
			}
		}
	}
}
