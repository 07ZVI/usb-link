package ipadncm

import (
	"context"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"unicode/utf16"
)

func identityStringFixture(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+len(u)*2)
	b[0], b[1] = byte(len(b)), 3
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2+i*2:], v)
	}
	return b
}

func TestIdentityDecoderPreservesRealStringsWithoutRepairOrFallback(t *testing.T) {
	for _, s := range []string{"ABCDEF1234567890", "00008030-0012345678901234", "iPad", "iPad Pro"} {
		got, status := parseUSBIdentityString(identityStringFixture(s))
		if got != s || status != "USB_STRING_VERIFIED" {
			t.Fatal("real descriptor altered", got, status)
		}
	}
	for _, b := range [][]byte{nil, {4, 3, 'i'}, {3, 3, 0}, {4, 2, 'i', 0}, {2, 3}, {4, 3, 0, 0}, {4, 3, 0, 0xd8}, {4, 3, 0, 0xdc}, {6, 3, 0, 0xd8, 'x', 0}, identityStringFixture(" iPad"), identityStringFixture("iPad "), identityStringFixture("iPad\n"), identityStringFixture(strings.Repeat("i", 129)), append(identityStringFixture("iPad"), 7)} {
		if got, _ := parseUSBIdentityString(b); got != "" {
			t.Fatal("damaged/missing descriptor became identity", b)
		}
	}
}

func TestIdentityLanguageListRequiresCompleteNonzeroDistinctIDs(t *testing.T) {
	if lang, _ := usbIdentityLanguage([]byte{6, 3, 9, 4, 4, 8}); lang != 0x0409 {
		t.Fatal("LANGID choice changed")
	}
	for _, b := range [][]byte{nil, {2, 3}, {4, 3, 9}, {5, 3, 9, 4, 0}, {4, 2, 9, 4}, {4, 3, 0, 0}, {6, 3, 9, 4, 9, 4}, {4, 3, 9, 4, 7}} {
		if lang, _ := usbIdentityLanguage(b); lang != 0 {
			t.Fatal("malformed language descriptor selected", b)
		}
	}
}

func TestDescriptorIdentitySurvivesOnlySamePhysicalBindingAndRawPair(t *testing.T) {
	a := usbDescriptorAttachment{root: `USB\VID_05AC&PID_12AB\ABCDEF1234567890`, hub: "actual-hub", port: 4, serial: "ABCDEF1234567890", product: "iPad", verified: true}
	if !a.same(a) {
		t.Fatal("same immutable descriptor pair rejected")
	}
	for _, mutate := range []func(*usbDescriptorAttachment){
		func(b *usbDescriptorAttachment) { b.verified = false },
		func(b *usbDescriptorAttachment) { b.root += "OTHER" },
		func(b *usbDescriptorAttachment) { b.hub += "OTHER" },
		func(b *usbDescriptorAttachment) { b.port++ },
		func(b *usbDescriptorAttachment) { b.serial += "OTHER" },
		func(b *usbDescriptorAttachment) { b.product = "iPad Air" },
		func(b *usbDescriptorAttachment) { b.product = "" },
	} {
		b := a
		mutate(&b)
		if a.same(b) {
			t.Fatal("device changed but retained permission", b)
		}
	}
	if !usbDescriptorRootMatches(a.root, a.serial) || usbDescriptorRootMatches(`USB\VID_05AC&PID_12AB\6&ABC123&0&4`, a.serial) || usbDescriptorRootMatches(a.root+"OTHER", a.serial) || usbDescriptorRootMatches(`USB\VID_05AC&PID_12AB&MI_02\ABCDEF1234567890`, a.serial) {
		t.Fatal("native root/actual descriptor mapping accepted location or child")
	}
}

func TestOneConnectionPermissionCannotLeakToNextAttemptOrDifferentPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	binding := usbDescriptorAttachment{root: `USB\VID_05AC&PID_12AB\ABCDEF1234567890`, hub: "actual-hub", port: 4, serial: "ABCDEF1234567890", product: "iPad", verified: true}
	if currentUSBDescriptorPermission(nil, binding, binding) || !currentUSBDescriptorPermission(ctx, binding, binding) {
		t.Fatal("one-connection proof missing owner scope")
	}
	moved := binding
	moved.port++
	if currentUSBDescriptorPermission(ctx, binding, moved) {
		t.Fatal("current connection permission survived a physical move")
	}
	cancel()
	if currentUSBDescriptorPermission(ctx, binding, binding) {
		t.Fatal("ended attempt remained implicitly allowed without remembered consent")
	}
}

func TestIdentityReadAndAuthorizationContainNoAppleSessionOrRawSerialExport(t *testing.T) {
	for _, filename := range []string{"usb_descriptor_identity_windows.go", "connection_settings_windows.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !(filename == "usb_descriptor_identity_windows.go" || fn.Name.Name == "Allow" || fn.Name.Name == "allowUSB" || fn.Name.Name == "AllowUSB") {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := ""
				switch x := call.Fun.(type) {
				case *ast.Ident:
					name = x.Name
				case *ast.SelectorExpr:
					name = x.Sel.Name
				}
				for _, forbidden := range []string{"queryModel", "muxDial", "AuthenticateCurrentUSB", "authenticatePair", "StartSession", "ReadFile", "WriteFile"} {
					if name == forbidden {
						t.Fatalf("identity path reaches %s", forbidden)
					}
				}
				return true
			})
		}
	}
	f, err := parser.ParseFile(token.NewFileSet(), "check_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "Device" {
			return true
		}
		for _, field := range spec.Type.(*ast.StructType).Fields.List {
			for _, name := range field.Names {
				if strings.Contains(strings.ToLower(name.Name), "serial") && ast.IsExported(name.Name) && name.Name != "USBSerialSHA256" && name.Name != "USBSerialIndex" && name.Name != "USBSerialReadStatus" && name.Name != "USBSerialFailureShape" && name.Name != "USBSerialPaddingNULUnits" {
					t.Fatal("raw serial exported by diagnostic Device", name.Name)
				}
			}
		}
		return false
	})
}
