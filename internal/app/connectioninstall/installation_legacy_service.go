package connectioninstall

import "fmt"

// Only the deletion-only legacy recovery path uses these display names.
// Display metadata never proves ownership or authorizes service execution;
// native callers still verify the fixed command, account, ACL, execution
// policy, missing installation root and stopped/PID-zero state.
func validateDeletedServiceMetadata(displayName, description, password string) error {
	if displayName != "USB Link" && displayName != CoreServiceName {
		return fmt.Errorf("REPAIR_SERVICE_CONFIG_CHANGED: displayName=%q", displayName)
	}
	if description != "USB Link core: owned USB networking, local UI IPC; no interactive Session0 UI." {
		return fmt.Errorf("REPAIR_SERVICE_CONFIG_CHANGED: description=%q", description)
	}
	if password != "" {
		return fmt.Errorf("REPAIR_SERVICE_CONFIG_CHANGED: unexpected password field")
	}
	return nil
}
