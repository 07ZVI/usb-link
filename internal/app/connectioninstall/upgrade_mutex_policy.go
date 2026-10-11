package connectioninstall

import "fmt"

const mutexAllAccess uint32 = 0x001f0001
const genericAllAccess uint32 = 0x10000000

// A named mutex is a kernel object, not a file. Compare effective mutex rights,
// not raw SDDL GA bytes or a file's inheritable/protected DACL representation.
// No additional principal, inherited ACE, callback ACE or unrecognized right
// is tolerated. SE_DACL_PROTECTED is diagnostic: the complete resulting DACL
// must already contain exactly these two non-inherited entries.
type mutexACE struct {
	Type, Flags uint8
	Mask        uint32
	Principal   string
}

func validateMutexPolicy(owner string, present bool, entries []mutexACE) error {
	if owner != "system" && owner != "administrators" && owner != "process_user" {
		return fmt.Errorf("reason=owner principal=%s", owner)
	}
	if !present {
		return fmt.Errorf("reason=dacl_null_or_missing")
	}
	if len(entries) != 2 {
		return fmt.Errorf("reason=ace_count actual=%d expected=2", len(entries))
	}
	seen := map[string]bool{}
	for i, ace := range entries {
		if ace.Type != 0 || ace.Flags != 0 {
			return fmt.Errorf("reason=ace_type_or_inheritance index=%d type=%d flags=0x%02x", i, ace.Type, ace.Flags)
		}
		if ace.Principal != "system" && ace.Principal != "administrators" || seen[ace.Principal] {
			return fmt.Errorf("reason=ace_principal index=%d principal=%s duplicate=%t", i, ace.Principal, seen[ace.Principal])
		}
		mask := ace.Mask
		if mask&genericAllAccess != 0 {
			mask = mask&^genericAllAccess | mutexAllAccess
		}
		if mask != mutexAllAccess {
			return fmt.Errorf("reason=ace_mask index=%d raw=0x%08x effective=0x%08x expected=0x%08x", i, ace.Mask, mask, mutexAllAccess)
		}
		seen[ace.Principal] = true
	}
	return nil
}
