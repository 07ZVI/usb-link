package ipadncm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestPhantomNativeMutationRestrictedToExactDocumentedProperty(t *testing.T) {
	b, err := os.ReadFile("portable_property_native_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(b)
	for _, name := range []string{"CM_Set_DevNode", "RegSetValue", "DeleteValue", "DIF_PROPERTYCHANGE", "DIF_REMOVE", "CONFIGFLAG_REINSTALL", "CM_Reenumerate_DevNode", "SetupDiRemoveDevice", "OpenKey"} {
		if strings.Contains(source, name) {
			t.Fatal("unapproved native mutation/path", name)
		}
	}
	f, err := parser.ParseFile(token.NewFileSet(), "portable_property_native_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	ast.Inspect(f, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "SetupDiSetDeviceRegistryProperty" {
			return true
		}
		if len(call.Args) != 4 {
			t.Fatal("property write shape changed")
		}
		prop, ok := call.Args[2].(*ast.SelectorExpr)
		if !ok || prop.Sel.Name != "SPDRP_CONFIGFLAGS" {
			t.Fatal("broader property mutation")
		}
		count++
		return true
	})
	if count != 1 {
		t.Fatalf("unexpected setter count %d", count)
	}
	if !strings.Contains(source, "CM_Get_DevNode_Registry_PropertyW") || !strings.Contains(source, "windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT") {
		t.Fatal("missing independent registry/present proof")
	}
}
func TestRestoreAuditReadOnlyAndSurvivesDescriptorEarlyReturn(t *testing.T) {
	b, e := os.ReadFile("network_only_live_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	audit := strings.Index(s, "readPortableLegacyAudit(dir)")
	descriptor := strings.Index(s, "snapshot := Inspect()")
	if audit < 0 || descriptor < audit || !strings.Contains(s, "PROTECTED_PORTABLE_RESTORE_AUDIT_UNREADABLE") {
		t.Fatal("audit lost behind descriptor/current-node early return")
	}
	f, e := parser.ParseFile(token.NewFileSet(), "network_only_live_windows.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	forbidden := map[string]bool{"savePortableLegacyAudit": true, "savePortableOriginalMetadata": true, "writePortableProtectedFile": true, "setPortableDisabled": true, "Start": true, "Stop": true}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if forbidden[name] {
			t.Fatal("state output mutates", name)
		}
		return true
	})
}
func TestRetiredIsolationCannotCaptureNewOriginalOrDisableNode(t *testing.T) {
	b, e := os.ReadFile("network_only_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, removed := range []string{"capturePortableOriginalBeforeDisable(", "r.Nodes = append(r.Nodes, node)", "setPortableDisabled("} {
		if strings.Contains(s, removed) {
			t.Fatal("retired isolation can capture/disable", removed)
		}
	}
	b, e = os.ReadFile("portable_property_store_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s = string(b)
	for _, required := range []string{"windows.GetSecurityInfo(h", "groupingACLMatches(actual, expected)", "windows.CREATE_NEW", "SecurityDescriptor: sd", "windows.FILE_FLAG_OPEN_REPARSE_POINT", "f.Sync()", "windows.MOVEFILE_WRITE_THROUGH", "portable restoration audit durable readback failed"} {
		if !strings.Contains(s, required) {
			t.Fatal("protected durable file gate missing", required)
		}
	}
}

func TestProtectedTempCreationUsesExclusiveCreationTimeConcreteFileACL(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "portable_property_store_windows.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, decl := range f.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Name.Name != "createPortableProtectedTemp" {
			continue
		}
		found = true
		ast.Inspect(function, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch selector.Sel.Name {
			case "CreateTemp", "SetSecurityInfo", "SetNamedSecurityInfo":
				t.Fatal("creation reverted to incompatible post-hoc ACL handle")
			case "CreateFile":
				if len(call.Args) != 7 {
					t.Fatal("CreateFile permission shape")
				}
				sa, ok := call.Args[3].(*ast.UnaryExpr)
				if !ok || sa.Op != token.AND {
					t.Fatal("creation omitted explicit security attributes")
				}
				creation, ok := call.Args[4].(*ast.SelectorExpr)
				if !ok || creation.Sel.Name != "CREATE_NEW" {
					t.Fatal("creation can replace existing file")
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("no protected creation helper")
	}
	b, e := os.ReadFile("portable_property_store_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if !strings.Contains(s, `D:P(A;;FA;;;SY)(A;;FA;;;BA)`) || strings.Contains(s, `D:P(A;;GA;;;SY)(A;;GA;;;BA)`) {
		t.Fatal("ACL mask not concrete FILE_ALL_ACCESS or principals changed")
	}
	if !strings.Contains(s, "windows.GENERIC_READ|windows.GENERIC_WRITE") || !strings.Contains(s, "groupingACLMatches(actual, sd)") {
		t.Fatal("opened file lacks read/proof permission")
	}
}
func TestRecoverySummaryExportCannotInitializePolicyOrModifyFiles(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "portable_property_store_windows.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	allowed := map[string]bool{"readPortableLegacyAudit": true, "portableRestoreSummaries": true, "Errorf": true}
	found := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ReadNetworkOnlyPropertyRestoreSummaries" {
			continue
		}
		found = true
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			if !allowed[name] {
				t.Fatal("summary export may mutate/init", name)
			}
			return true
		})
	}
	if !found {
		t.Fatal("no pre-InitNetworkOnly independent reader")
	}
}
