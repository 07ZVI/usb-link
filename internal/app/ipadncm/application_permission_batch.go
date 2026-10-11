package ipadncm

import "strings"

// The caller must also require successful process completion. A status emitted
// by the first script never grants networking after the second script fails.
func applicationPermissionBatchReady(output string) bool {
	return strings.ReplaceAll(strings.TrimSpace(output), "\r\n", "\n") == "OWNED_FIREWALL_READY\nUSB_CORE_PERMISSION_READY"
}
