package ipadncm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"
)

func TestUnifiedRoutingAndDisconnectDoNotConfuseMacAndIPad(t *testing.T) {
	mac := `USB\VID_05AC&PID_1903\ABCDEF123456`
	ipad := `USB\VID_05AC&PID_12AB\ABCDEF987654`
	for _, tc := range []struct {
		ids      []string
		complete bool
		kind     string
		absent   bool
	}{
		{[]string{mac, `USB\VID_05AC&PID_1903&MI_00\CHILD`}, true, "Mac", false},
		{[]string{ipad}, true, "iPad", false}, {[]string{ipad, mac}, true, "", false},
		{[]string{`USB\VID_05AC&PID_12A8\OTHERDEVICE`}, true, "", false},
		{nil, true, "", true}, {nil, false, "", false},
	} {
		kind, p := idleUSBPresenceFromIDs(tc.ids, tc.complete)
		if kind != tc.kind || p.absent != tc.absent || p.readable != tc.complete {
			t.Fatal("routing", tc, kind, p)
		}
	}
	var gate idleReconnectGate
	now := time.Now()
	_, none := idleUSBPresenceFromIDs(nil, true)
	_, attached := idleUSBPresenceFromIDs([]string{mac}, true)
	gate.detached(now, none)
	if gate.detached(now.Add(time.Minute), attached) || gate.detached(now.Add(61*time.Second), none) {
		t.Fatal("Mac incorrectly proved detach")
	}
}

func TestNetworkModeReuseNeedsQualifiedSourceAndActiveNCM(t *testing.T) {
	source := "CURRENT_USB_IDENTIFIERS_AND_NCM_LAYOUT_NO_APPLE_SESSION"
	if !networkModeIdentity(source, "", "NCM_DESCRIPTORS_PRESENT", true) {
		t.Fatal("network-only proof rejected")
	}
	for _, tc := range []struct {
		source, err, status string
		active              bool
	}{
		{"FRESH_APPLE_USB_QUERY", "", "NCM_DESCRIPTORS_PRESENT", true},
		{source, "error", "NCM_DESCRIPTORS_PRESENT", true},
		{source, "", "NCM_DESCRIPTORS_PRESENT", false}, {source, "", "INCOMPLETE", true},
	} {
		if networkModeIdentity(tc.source, tc.err, tc.status, tc.active) {
			t.Fatal("unqualified mode reused")
		}
	}
}

// The authorization path must stay independent of Apple session/credentials.
func TestUSBConsentCannotInitiateApplePairingSession(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "connection_settings_windows.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	found := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "Allow" && fn.Name.Name != "AllowUSB" && fn.Name.Name != "allowUSB") {
			continue
		}
		found++
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch x := c.Fun.(type) {
			case *ast.Ident:
				name = x.Name
			case *ast.SelectorExpr:
				name = x.Sel.Name
			}
			for _, bad := range []string{"AuthenticateCurrentUSB", "authenticatePair", "queryModel", "muxDial", "StartSession", "ReadFile"} {
				if name == bad {
					t.Fatalf("USB consent reaches %s", bad)
				}
			}
			return true
		})
	}
	if found != 3 {
		t.Fatal("missing consent entrypoints")
	}
}
