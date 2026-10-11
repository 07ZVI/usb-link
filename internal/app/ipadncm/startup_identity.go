package ipadncm

import "strings"

// This identity may be reused only inside the current launch, after the caller
// separately verifies the unchanged physical USB target and active configuration.
func startupModeIdentity(product, metadataError, status string, active bool) bool {
	return active && strings.HasPrefix(product, "iPad") && metadataError == "" &&
		(status == "NCM_DESCRIPTORS_PRESENT" || status == "NCM_DESCRIPTORS_AFTER_REQUEST")
}

func networkModeIdentity(source, metadataError, status string, active bool) bool {
	return active && metadataError == "" && (source == "CURRENT_USB_IDENTIFIERS_AND_NCM_LAYOUT_NO_APPLE_SESSION" || source == "CURRENT_LAUNCHER_SUCCESSFUL_MODE_EXACT_ROOT") && (status == "NCM_DESCRIPTORS_PRESENT" || status == "NCM_DESCRIPTORS_AFTER_REQUEST")
}
