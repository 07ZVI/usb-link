package netconfig

import (
	"strings"
	"sync"
	"time"
)

type NetworkScriptFailure struct {
	AtUTC      string `json:"at_utc"`
	Stage      string `json:"stage"`
	Code       string `json:"code"`
	DurationMS int64  `json:"duration_ms"`
}

var networkScriptFailures struct {
	sync.Mutex
	items []NetworkScriptFailure
}

// Only fixed product markers leave this process. Provider exceptions, paths,
// scripts and device identifiers must not become remote diagnostic fields.
func networkScriptFailureCode(output string) string {
	for _, code := range []string{"USB_HOST_DRIVER_MAPPING_UNPROVEN", "USB_HOST_DRIVER_INSTANCE_UNPROVEN", "USB_HOST_DRIVER_IDENTITY_UNPROVEN"} {
		if strings.Contains(output, code) {
			return code
		}
	}
	return "SCRIPT_FAILED"
}

func recordNetworkScriptFailure(script, code string, elapsed time.Duration) {
	stage := "network_configuration"
	if strings.Contains(script, "USB_HOST_DRIVER_IDENTITY_VERIFIED") {
		stage = "shared_host_driver_identity"
	}
	if strings.Contains(script, "USB-CoreSnapshot") {
		stage = "owned_core_permissions"
	}
	item := NetworkScriptFailure{time.Now().UTC().Format(time.RFC3339Nano), stage, code, elapsed.Milliseconds()}
	networkScriptFailures.Lock()
	defer networkScriptFailures.Unlock()
	if len(networkScriptFailures.items) == 16 {
		networkScriptFailures.items = networkScriptFailures.items[1:]
	}
	networkScriptFailures.items = append(networkScriptFailures.items, item)
}

func NetworkScriptFailureDiagnostics() []NetworkScriptFailure {
	networkScriptFailures.Lock()
	defer networkScriptFailures.Unlock()
	return append([]NetworkScriptFailure{}, networkScriptFailures.items...)
}
