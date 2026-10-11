package ipadncm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestDriverAdmissionReaderCannotMutateServiceNodeOrProtectedReceipt(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "network_only_driver_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"Start": true, "Stop": true, "Control": true, "UpdateConfig": true, "CreateDirectory": true, "CreateFile": true, "WriteFile": true, "saveNetworkOnlyReceipt": true, "writeNetworkOnlyFile": true, "EnsureNetworkOnly": true, "applyNetworkOnlyService": true, "setPortableDisabled": true}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			if forbidden[name] {
				t.Fatal("read-only admission can mutate", name)
			}
		}
		return true
	})
}

func TestMainBoundDriverDoesNotRequireOrStartAMDS(t *testing.T) {
	b, e := os.ReadFile("../launcher/driver_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	bound := strings.Index(s, "if d.AlreadyBound {")
	repair := strings.Index(s, "d.Consent = dialog(")
	start := strings.Index(s, "if !ensureService(&d)")
	if bound < 0 || repair < bound || start < repair || !strings.Contains(s[bound:repair], "return") {
		t.Fatal("existing official driver cannot bypass consented service repair")
	}
	if strings.Contains(s, "d.AlreadyBound && d.ServiceBefore") || strings.Contains(s, "NetworkOnlyDriverAdmission(d.Before)") {
		t.Fatal("default driver path still depends on retired AMDS policy")
	}
}
