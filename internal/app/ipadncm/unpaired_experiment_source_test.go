package ipadncm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func unpairedSourceFunction(t *testing.T, path, name string) *ast.FuncDecl {
	t.Helper()
	f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("missing %s", name)
	return nil
}
func unpairedCalls(fn ast.Node) map[string]token.Pos {
	r := map[string]token.Pos{}
	ast.Inspect(fn, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			switch f := c.Fun.(type) {
			case *ast.Ident:
				r[f.Name] = c.Pos()
			case *ast.SelectorExpr:
				r[f.Sel.Name] = c.Pos()
			}
		}
		return true
	})
	return r
}
func TestUnpairedAbsentPreparationIsReadOnlyUntilOwnerAndNoPairAPIs(t *testing.T) {
	prep := unpairedSourceFunction(t, "unpaired_experiment_windows.go", "unpairedPreparationNative")
	native := unpairedCalls(prep)
	for _, name := range []string{"idlePnPIDs", "verifyInstalledAppleControlDriver", "networkOnlyDriverStoreProtected", "Query", "Config"} {
		if native[name] == 0 {
			t.Fatalf("missing fresh absent-prep proof %s", name)
		}
	}
	for _, name := range []string{"Start", "Stop", "Control", "UpdateConfig", "EnsureNetworkOnly", "applyNetworkOnlyService", "saveNetworkOnlyReceipt", "CreateFile", "WriteFile", "ReadFile", "Remove", "Rename"} {
		if native[name] != 0 {
			t.Fatalf("absent preflight mutates or opens arbitrary content via %s", name)
		}
	}
	driver := unpairedSourceFunction(t, "unpaired_experiment_windows.go", "unpairedExperimentDriverAdmission")
	c := unpairedCalls(driver)
	for _, name := range []string{"Inspect", "networkOnlyDriverRootHealthy", "verifyInstalledAppleControlDriver", "readNetworkOnlyReceipt", "Query", "Config", "unpairedExpectedServicePolicy"} {
		if c[name] == 0 {
			t.Fatalf("driver gate lacks %s", name)
		}
	}
	for _, name := range []string{"Start", "Stop", "UpdateConfig", "EnsureNetworkOnly", "RecordCurrentAMDSModeProof", "SetIPadCandidateStage"} {
		if c[name] != 0 {
			t.Fatalf("read-only experiment admission mutates %s", name)
		}
	}
	f, e := parser.ParseFile(token.NewFileSet(), "unpaired_experiment_windows.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	all := unpairedCalls(f)
	for _, name := range []string{"queryModel", "Pair", "SavePairRecord", "DeletePairRecord", "ReadPairRecord", "SetIPadCandidateStage", "RecordCurrentAMDSModeProof", "writeNetworkOnlyFile"} {
		if all[name] != 0 {
			t.Fatalf("experiment changed pairing, proof or saved choice: %s", name)
		}
	}
}
func TestUnpairedPreflightReadbackHasNoMutationOrConsent(t *testing.T) {
	fn := unpairedSourceFunction(t, "unpaired_experiment_windows.go", "InspectUnpairedExperimentPreflight")
	c := unpairedCalls(fn)
	for _, name := range []string{"Inspect", "networkOnlyDriverRootHealthy", "verifyInstalledAppleControlDriver", "inspect"} {
		if c[name] == 0 {
			t.Fatalf("fresh readonly preflight lacks %s", name)
		}
	}
	for _, name := range []string{"stopUnpairedExperiment", "RequestUnpairedExperimentPreparation", "Allow", "BeginSecurityAttempt", "EnsureNetworkOnly", "Start", "Control", "UpdateConfig", "RunNetworkOnlyAppleControl", "CreateFile", "ReadFile", "Remove", "Rename"} {
		if c[name] != 0 {
			t.Fatalf("readonly preflight mutates/authorizes or reads contents: %s", name)
		}
	}
}
