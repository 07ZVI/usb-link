package internet

import (
	"strings"
	"testing"
)

// Mobile Hotspot is detected read-only via WinRT (HNetShare does not reliably flag it) and must precede route selection.
func TestPreflightScriptDetectsMobileHotspotReadOnly(t *testing.T) {
	i := strings.Index(preflightScript, "INTERNET_MOBILE_HOTSPOT_CONFLICT")
	if i < 0 || i > strings.Index(preflightScript, "$routes=") || strings.Index(preflightScript, "INTERNET_EXISTING_ICS_CONFLICT") > i {
		t.Fatal("hotspot conflict must follow ICS check and precede route selection")
	}
	for _, need := range []string{"NetworkOperatorTetheringManager", "TetheringOperationalState", "GetInternetConnectionProfile"} {
		if !strings.Contains(preflightScript, need) {
			t.Fatal("missing " + need)
		}
	}
	for _, bad := range []string{"StopTetheringAsync", "StartTetheringAsync", "ConfigureAccessPoint"} {
		if strings.Contains(preflightScript, bad) {
			t.Fatal("preflight must not modify hotspot: " + bad)
		}
	}
}
