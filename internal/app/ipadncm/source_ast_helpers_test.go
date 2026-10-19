package ipadncm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Source-shape helpers shared by the tests that pin which APIs a function may
// call (simplified network, NCM Direct observation).
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
