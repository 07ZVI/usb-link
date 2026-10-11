package ipadncm

import "testing"

func TestApplicationPermissionBatchRequiresBothOrderedReadbacks(t *testing.T) {
	for _, output := range []string{"OWNED_FIREWALL_READY\nUSB_CORE_PERMISSION_READY", "OWNED_FIREWALL_READY\r\nUSB_CORE_PERMISSION_READY\r\n"} {
		if !applicationPermissionBatchReady(output) {
			t.Fatal("complete readbacks rejected", output)
		}
	}
	for _, output := range []string{"", "OWNED_FIREWALL_READY", "USB_CORE_PERMISSION_READY", "USB_CORE_PERMISSION_READY\nOWNED_FIREWALL_READY", "OWNED_FIREWALL_READY\nFAILED\nUSB_CORE_PERMISSION_READY", "OWNED_FIREWALL_READY\nUSB_CORE_PERMISSION_READY\nUNEXPECTED", "OWNED_FIREWALL_READY\n\nUSB_CORE_PERMISSION_READY"} {
		if applicationPermissionBatchReady(output) {
			t.Fatal("partial or unexpected output admitted", output)
		}
	}
}
