package netconfig

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNetworkScriptFailuresAreBoundedAndRedacted(t *testing.T) {
	networkScriptFailures.Lock()
	networkScriptFailures.items = nil
	networkScriptFailures.Unlock()
	for i := 0; i < 20; i++ {
		code := networkScriptFailureCode("provider private/path PNP SECRET error USB_HOST_DRIVER_INSTANCE_UNPROVEN")
		recordNetworkScriptFailure("USB_HOST_DRIVER_IDENTITY_VERIFIED private-script", code, time.Millisecond)
	}
	got := NetworkScriptFailureDiagnostics()
	if len(got) != 16 {
		t.Fatalf("count=%d", len(got))
	}
	b, _ := json.Marshal(got)
	for _, secret := range []string{"private", "SECRET", "PNP", "provider"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("unredacted output")
		}
	}
	got[0].Code = "changed"
	if NetworkScriptFailureDiagnostics()[0].Code == "changed" {
		t.Fatal("snapshot aliases collector")
	}
	if networkScriptFailureCode("arbitrary raw exception") != "SCRIPT_FAILED" {
		t.Fatal("raw exception escaped")
	}
}
