package ipadncm

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestTrustRevokePairHandlesHaveNoContentReadAccess(t *testing.T) {
	fset := token.NewFileSet()
	src, err := parser.ParseFile(fset, "trust_revoke_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, decl := range src.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "trustRevokeOpenRecord" {
			continue
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "CreateFile" {
				return true
			}
			if len(call.Args) != 7 {
				t.Fatal("unexpected CreateFile signature")
			}
			var access bytes.Buffer
			if err := format.Node(&access, fset, call.Args[1]); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(access.String(), "GENERIC_READ") || strings.Contains(access.String(), "FILE_READ_DATA") {
				t.Fatal("pair handle gained content read access")
			}
			if !strings.Contains(access.String(), "DELETE") || !strings.Contains(access.String(), "FILE_READ_ATTRIBUTES") || !strings.Contains(access.String(), "WRITE_OWNER") {
				t.Fatal("pair handle no longer supports bound move/metadata/protected ownership")
			}
			return true
		})
	}
	if !found {
		t.Fatal("pair handle entry not found")
	}
	for _, decl := range src.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "ReadFile" || sel.Sel.Name == "ReadAll" && fn.Name.Name != "trustRevokeWriteMetadata" {
				t.Fatalf("content read outside own operation-metadata helper: %s", fn.Name.Name)
			}
			return true
		})
	}
}

func TestTrustRevokeSyntheticSelfTestHasNoAppleOrCallerPaths(t *testing.T) {
	b, err := os.ReadFile("trust_revoke_selftest_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	src, err := parser.ParseFile(token.NewFileSet(), "trust_revoke_selftest_windows.go", b, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range src.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "RunTrustRecycleNativeSelfTest" {
			continue
		}
		if len(fn.Type.Params.List) != 0 {
			t.Fatal("synthetic selftest accepts external paths")
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if fun.Name == "Inspect" || fun.Name == "trustRevokeSource" || fun.Name == "trustRevokeCurrentTarget" {
					t.Fatal("selftest touches live pair/USB state")
				}
			case *ast.SelectorExpr:
				if fun.Sel.Name == "RemoveAll" || fun.Sel.Name == "ReadFile" || fun.Sel.Name == "ReadAll" {
					t.Fatal("selftest widened file traversal/content access")
				}
			}
			return true
		})
		return
	}
	t.Fatal("synthetic selftest entry not found")
}
