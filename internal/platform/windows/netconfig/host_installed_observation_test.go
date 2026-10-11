package netconfig

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Provider observations are intentionally rejected by the old script parser:
// an installed-node diagnostic must never turn into successful identity proof.
func TestInstalledNodeObservationCannotBecomeScriptIdentityAuthority(t *testing.T) {
	for _, c := range []HostInstalledCandidateObservation{
		{IdentityValid: true, StateReadable: true},
		{StateReadable: true, Problem: 22, IdentityError: "USB_HOST_NATIVE_NODE_STATE_UNPROVEN"},
		{StateReadable: false, StateError: 13, IdentityError: "USB_HOST_NATIVE_PROPERTY_UNREADABLE"},
	} {
		d := HostIdentityDiagnostic{NativeReadback: true, Phase: "native_pnp_enumeration", InstalledNodes: &HostInstalledNodeObservation{ObservationOnly: true, Complete: true, Enumerated: 1, BindingMatches: 1, Candidates: []HostInstalledCandidateObservation{c}}}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = decodeHostIdentityDiagnostic(b); err == nil {
			t.Fatal("installed-node observation became script identity proof")
		}
	}
	// Injection into an otherwise complete legacy observation is rejected too.
	for _, v := range []string{`{"observation_only":true,"binding_matches":1}`, `{"observation_only":false,"binding_matches":1}`} {
		b := strings.TrimSuffix(validHostDiagnostic, "}") + `,"installed_nodes":` + v + `}`
		if _, err := decodeHostIdentityDiagnostic([]byte(b)); err == nil {
			t.Fatal("installed-node field accepted as legacy authority")
		}
	}
}

// This static boundary supplements the Windows compile and existing strict
// native-identity fixtures. It does not claim SetupAPI was run on macOS.
func TestInstalledNodeObservationHasOnlyReadonlyNativeCalls(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "host_installed_observation_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"windows.GUIDFromString": true, "windows.SetupDiGetClassDevsEx": true,
		"set.Close": true, "set.EnumDeviceInfo": true, "set.OpenDevRegKey": true,
		"nativeHostRegistryGUID": true, "windows.RegCloseKey": true,
		"strings.EqualFold": true, "len": true, "readNativeHostNode": true,
		"err.Error": true, "windows.CM_Get_DevNode_Status": true,
		"set.DeviceInstallParams": true, "uint32": true, "append": true,
		"readNativeHostNonpresentProof": true,
	}
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch x := c.Fun.(type) {
		case *ast.Ident:
			name = x.Name
		case *ast.SelectorExpr:
			if a, ok := x.X.(*ast.Ident); ok {
				name = a.Name + "." + x.Sel.Name
			}
		}
		if !allowed[name] {
			t.Errorf("installed-node observer calls outside readonly boundary: %s", name)
		}
		return true
	})
	b, err := os.ReadFile("host_installed_observation_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, bound := range []string{"i < 4096", "len(o.Candidates) == 4", "o.CandidatesTruncated = true", "ObservationOnly: true", "USB_HOST_INSTALLED_ENUMERATION_LIMIT"} {
		if !strings.Contains(s, bound) {
			t.Fatal("missing bounded observation guard", bound)
		}
	}
	for _, typ := range []any{HostInstalledNodeObservation{}, HostInstalledCandidateObservation{}} {
		b, err := json.Marshal(typ)
		if err != nil || strings.Contains(string(b), `"instance"`) || strings.Contains(string(b), `"registry_path"`) || strings.Contains(string(b), `"guid"`) {
			t.Fatal("installed-node diagnostic exports sensitive identity", string(b), err)
		}
	}
}
