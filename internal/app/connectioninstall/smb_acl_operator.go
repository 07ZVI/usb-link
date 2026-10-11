package connectioninstall

import "fmt"

// Directory selection and data reads retain the ordinary desktop identity.
// Only the approved permission mutation uses the already privileged manager.
func validateSMBACLAdministrator(operator, desktop shareIdentity, boundOwner string) error {
	if desktop.SID == "" || desktop.Elevated || desktop.Session == 0 || desktop.Session == ^uint32(0) {
		return fmt.Errorf("SMB_ACL_DESKTOP_IDENTITY_INVALID")
	}
	if operator.SID == "S-1-5-18" {
		if operator.Session != 0 || boundOwner != desktop.SID {
			return fmt.Errorf("SMB_ACL_BOUND_SERVICE_REQUIRED")
		}
		return nil
	}
	if !operator.Elevated || operator.SID != desktop.SID || operator.Session != desktop.Session || boundOwner != "" && boundOwner != desktop.SID {
		return fmt.Errorf("SMB_ACL_SAME_OWNER_ADMIN_REQUIRED")
	}
	return nil
}
