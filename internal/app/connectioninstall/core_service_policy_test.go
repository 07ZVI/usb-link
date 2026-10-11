package connectioninstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func testCoreBinding() CoreServiceBinding {
	return CoreServiceBinding{Version: 1, Product: ProductID, OwnerSID: "S-1-5-21-1-2-3-1001", Executable: `C:\Program Files\USB Link\0.8.98\USB-Link.exe`, SHA256: strings.Repeat("a", 64)}
}
func TestCoreBindingRejectsForgedShapeAndSystemOwner(t *testing.T) {
	valid, _ := json.Marshal(testCoreBinding())
	if _, e := parseCoreBinding(valid); e != nil {
		t.Fatal(e)
	}
	for name, input := range map[string]string{
		"duplicate":     strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1),
		"trailing":      string(valid) + `{}`,
		"unknown":       strings.Replace(string(valid), `"version":1`, `"version":1,"trusted":true`, 1),
		"missing_hash":  strings.Replace(string(valid), `,"sha256":"`+strings.Repeat("a", 64)+`"`, "", 1),
		"system_owner":  strings.Replace(string(valid), "S-1-5-21-1-2-3-1001", "S-1-5-18", 1),
		"wrong_product": strings.Replace(string(valid), ProductID, "foreign", 1),
		"upper_hash":    strings.Replace(string(valid), strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"oversize":      strings.Repeat(" ", 4096) + string(valid),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := parseCoreBinding([]byte(input)); e == nil {
				t.Fatal("accepted invalid binding")
			}
		})
	}
}
func TestCoreServiceRejectsForeignCommandAndConfiguration(t *testing.T) {
	exe := testCoreBinding().Executable
	for _, start := range []uint32{2, 3} {
		if e := validateCoreServiceConfig(exe, "LocalSystem", 0x10, start, false, []string{exe, CoreServiceArgument}); e != nil {
			t.Fatal(e)
		}
	}
	for name, args := range map[string][]string{"foreign_binary": {"foreign", CoreServiceArgument}, "injected_argument": {exe, CoreServiceArgument, "--run"}, "old_mode": {exe, "--background-service"}, "missing_argument": {exe}} {
		t.Run(name, func(t *testing.T) {
			if validateCoreServiceConfig(exe, "LocalSystem", 0x10, 2, false, args) == nil {
				t.Fatal("accepted changed command")
			}
		})
	}
	for name, v := range map[string]struct {
		account     string
		kind, start uint32
		delayed     bool
	}{"foreign_account": {"AVA", 0x10, 2, false}, "interactive_system": {"LocalSystem", 0x110, 2, false}, "disabled": {"LocalSystem", 0x10, 4, false}, "delayed": {"LocalSystem", 0x10, 2, true}} {
		t.Run(name, func(t *testing.T) {
			if validateCoreServiceConfig(exe, v.account, v.kind, v.start, v.delayed, []string{exe, CoreServiceArgument}) == nil {
				t.Fatal("accepted changed service")
			}
		})
	}
}
func TestCoreTransitionRejectsAmbiguousRollbackIdentity(t *testing.T) {
	old := testCoreBinding()
	next := old
	next.Executable = strings.Replace(old.Executable, "0.8.98", "0.8.99", 1)
	next.SHA256 = strings.Repeat("b", 64)
	for name, v := range map[string]coreServiceTransition{"first_install": {Version: 1, Next: next}, "migration": {Version: 1, Previous: &old, Next: next}} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(v)
			got, e := parseCoreTransition(b)
			if e != nil || got.Next != next {
				t.Fatalf("valid transition rejected: %v", e)
			}
		})
	}
	v := coreServiceTransition{Version: 1, Previous: &old, Next: next}
	good, _ := json.Marshal(v)
	for name, input := range map[string]string{
		"duplicate_phase":        strings.Replace(string(good), `"version":1`, `"version":1,"version":1`, 1),
		"duplicate_previous":     strings.Replace(string(good), `"previous":`, `"previous":null,"previous":`, 1),
		"duplicate_nested_owner": strings.Replace(string(good), `"owner_sid":"`+old.OwnerSID+`"`, `"owner_sid":"`+old.OwnerSID+`","owner_sid":"`+old.OwnerSID+`"`, 1),
		"owner_transfer":         strings.Replace(string(good), old.OwnerSID, "S-1-5-21-7-8-9-1001", 1),
		"missing_previous":       `{"version":1,"next":` + string(mustCoreJSON(next)) + `}`,
		"trailing":               string(good) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := parseCoreTransition([]byte(input)); e == nil {
				t.Fatal("accepted ambiguous migration")
			}
		})
	}
}
func mustCoreJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func TestCoreWorkerCapabilityDoesNotAdoptLegacyPIDProtocol(t *testing.T) {
	for _, v := range []string{"0.8.97", "0.8.9", "0.7.999", "-1.9.1", "0.8.98junk", "0.8.98.1", "", "0.8"} {
		if coreWorkerSupported(v) {
			t.Fatalf("accepted %q", v)
		}
	}
	for _, v := range []string{"0.8.98", "0.8.99", "0.9.0", "1.0.0"} {
		if !coreWorkerSupported(v) {
			t.Fatalf("rejected %q", v)
		}
	}
}
