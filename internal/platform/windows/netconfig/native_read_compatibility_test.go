package netconfig

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"syscall"
	"testing"
)

func TestNativeReadCompatibilityEveryConstraintDifference(t *testing.T) {
	s, good := firewallPolicyFixture()
	fields := nativeFirewallReadDifferences(s, good, nil)
	if len(fields) != 36 || !nativeReadStageFieldsMatch(fields) {
		t.Fatalf("complete fixture: count %d", len(fields))
	}
	for key := range good {
		t.Run(key, func(t *testing.T) {
			for _, missing := range []bool{false, true} {
				changed := maps.Clone(good)
				if missing {
					delete(changed, key)
				} else {
					changed[key] = []string{"S:private-changed-value"}
				}
				fields := nativeFirewallReadDifferences(s, changed, nil)
				if len(fields) != 36 || nativeReadStageFieldsMatch(fields) {
					t.Fatal("incomplete/changed rule reported matching")
				}
				failures := 0
				for _, f := range fields {
					if f.Status == "mismatch" || f.Status == "unavailable" {
						failures++
					}
				}
				if failures != 1 {
					t.Fatalf("difference is not isolated: %d", failures)
				}
			}
		})
	}
}

func TestNativeReadCompatibilityAbsenceIsTypedAndFieldSpecific(t *testing.T) {
	s, good := firewallPolicyFixture()
	for _, key := range []string{"/Platforms", "/Owner", "/PackageFamilyName", "/PolicyAppId", "MSFT_NetApplicationFilter/Package", "/RemoteDynamicKeywordAddresses", "MSFT_NetProtocolPortFilter/IcmpType"} {
		got := maps.Clone(good)
		got[key] = []string{"NULL"}
		if !nativeReadStageFieldsMatch(nativeFirewallReadDifferences(s, got, nil)) {
			t.Fatalf("documented explicit absence rejected: %s", key)
		}
	}
	got := maps.Clone(good)
	got["MSFT_NetNetworkLayerSecurityFilter/LocalUsers"] = []string{"NULL"}
	got["MSFT_NetNetworkLayerSecurityFilter/Authentication"] = []string{"N:1"}
	if nativeReadStageFieldsMatch(nativeFirewallReadDifferences(s, got, nil)) {
		t.Fatal("authentication policy changed alongside NULL user projection")
	}
	got = maps.Clone(good)
	got["MSFT_NetApplicationFilter/AppPath"] = []string{`S:C:\old\USB-Link.exe`}
	if nativeReadStageFieldsMatch(nativeFirewallReadDifferences(s, got, nil)) {
		t.Fatal("old executable accepted by diagnostic comparison")
	}
}

func TestNativeReadCompatibilityOutputDoesNotCarryValuesOrCallerNames(t *testing.T) {
	s, got := firewallPolicyFixture()
	got["/foreign-property-private"] = []string{"S:private-value"}
	got["MSFT_NetApplicationFilter/AppPath"] = []string{`S:C:\private-path\USB-Link.exe`}
	n := uint32(81234)
	observed := map[string]NativeReadCompatibilityField{
		"MSFT_NetApplicationFilter/AppPath": {Class: "private-class", Property: "private-property", Status: "private-status", Projection: "private-projection", Number: &n},
		"/Enabled":                          {Projection: "unsigned_integer", Number: &n},
	}
	fields := nativeFirewallReadDifferences(s, got, observed)
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "private-") || strings.Contains(string(b), `C:\\`) || len(fields) != 36 {
		t.Fatalf("private input escaped: %s", b)
	}
	for _, f := range fields {
		if f.Property == "AppPath" && (f.Number != nil || f.Projection != "") {
			t.Fatal("untyped sensitive metadata copied")
		}
		if f.Property == "Enabled" && (f.Number == nil || *f.Number != n) {
			t.Fatal("fixed enum numeric observation omitted")
		}
	}
}

type nativeReadHRESULTTestError struct{ value uint32 }

func (e nativeReadHRESULTTestError) Error() string         { return "private-native-error" }
func (e nativeReadHRESULTTestError) NativeHRESULT() uint32 { return e.value }

func TestNativeReadCompatibilityTypedErrorsOnly(t *testing.T) {
	hr, code := nativeReadErrorNumbers(fmt.Errorf("private wrapper: %w", nativeReadHRESULTTestError{0x80070005}))
	if hr != 0x80070005 || code != 0 {
		t.Fatal(hr, code)
	}
	hr, code = nativeReadErrorNumbers(fmt.Errorf("private wrapper: %w", syscall.Errno(5)))
	if hr != 0 || code != 5 {
		t.Fatal(hr, code)
	}
	hr, code = nativeReadErrorNumbers(fmt.Errorf("HRESULT=0x80070005 path=C:\\private"))
	if hr != 0 || code != 0 {
		t.Fatal("raw error text parsed")
	}
	hr, _ = nativeReadErrorNumbers(nativeReadHRESULTTestError{1})
	if hr != 0 {
		t.Fatal("success HRESULT labelled failure")
	}
	if nativeReadStageFieldsMatch(nil) {
		t.Fatal("empty read treated as proof")
	}
}
