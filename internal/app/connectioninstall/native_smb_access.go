package connectioninstall

import "fmt"

// Empty receipts predate per-share access and retain their existing grant.
func validSMBAccess(access string) bool {
	return access == "" || access == "read" || access == "modify" || access == "none"
}

func smbAccessMask(access string) (string, error) {
	switch access {
	case "":
		return "FA", nil
	case "read":
		return "0x1200a9", nil
	case "modify":
		return "0x1301bf", nil
	case "none":
		return "", nil
	default:
		return "", fmt.Errorf("NATIVE_SMB_ACCESS_INVALID")
	}
}

func displayedSMBAccess(access string, present bool) string {
	if !present {
		return "none"
	}
	if access == "" {
		return "modify"
	}
	return access
}

// Share permissions apply on both NTFS and filesystems without a local DACL.
// Every change remains bound to the selected directory; NTFS additionally
// requires the protected ACL recovery identity.
func verifiedSMBAccessRoot(persistentACL, selectedIdentity, journalIdentity bool) bool {
	return selectedIdentity && (!persistentACL || journalIdentity)
}
