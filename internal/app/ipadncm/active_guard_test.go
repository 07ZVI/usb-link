package ipadncm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

func TestCachedPhysicalLocationDoesNotAcceptUnknownOrMovedDevice(t *testing.T) {
	a := []string{"PCIROOT(0)#PCI(0101)#USBROOT(0)#USB(3)", "ACPI(PCI0)#USB(3)"}
	if !sameCachedLocation(a, []string{"acpi(pci0)#usb(3)", a[0]}) {
		t.Fatal("equivalent physical cache rejected")
	}
	for _, b := range [][]string{nil, {a[0]}, {a[0], "ACPI(PCI0)#USB(4)"}, {a[0], a[0]}, {a[0], ""}} {
		if sameCachedLocation(a, b) {
			t.Fatal("unconfirmed or moved physical target accepted", b)
		}
	}
}

// This regression guard protects the live streaming path, not initialization:
// it must retain fresh PnP/mapping checks without reaching USB hub requests.
func TestActiveGuardCannotReachUSBDescriptorOrControlReads(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	graph := map[string][]string{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := ""
				switch e := c.Fun.(type) {
				case *ast.Ident:
					name = e.Name
				case *ast.SelectorExpr:
					name = e.Sel.Name
				}
				graph[fn.Name.Name] = append(graph[fn.Name.Name], name)
				return true
			})
		}
	}
	seen := map[string]bool{}
	var visit func(string, []string)
	visit = func(n string, path []string) {
		if seen[n] {
			return
		}
		seen[n] = true
		path = append(append([]string(nil), path...), n)
		for _, forbidden := range []string{"Inspect", "inventory", "ioctl", "descriptor", "open", "RunAppleControlWithLease"} {
			if n == forbidden {
				t.Fatalf("active guard reaches USB request: %s", strings.Join(path, " -> "))
			}
		}
		for _, child := range graph[n] {
			if _, ok := graph[child]; ok {
				visit(child, path)
			}
		}
	}
	if len(graph["currentActivePeerAdapter"]) == 0 {
		t.Fatal("missing active guard")
	}
	visit("currentActivePeerAdapter", nil)
	if !seen["inventoryPnP"] || !seen["sameCachedLocation"] || !seen["readNCMAdapters"] || !seen["readMappedAdapter"] {
		t.Fatal("lost live physical/adapter checks", seen)
	}
}
