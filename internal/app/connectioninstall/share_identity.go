package connectioninstall

import "fmt"

// File sharing may use only a non-elevated identity belonging to this account
// in this interactive session. An administrator entered at UAC is not the
// desktop owner when these identities differ.
type shareIdentity struct {
	SID      string
	Session  uint32
	Elevated bool
}

func validateShareIdentity(owner, candidate shareIdentity) error {
	if candidate.Elevated {
		return fmt.Errorf("SHARE_STANDARD_USER_TOKEN_REQUIRED")
	}
	if owner.SID == "" || owner.SID != candidate.SID || owner.Session != candidate.Session {
		return fmt.Errorf("SHARE_USER_IDENTITY_MISMATCH")
	}
	return nil
}
