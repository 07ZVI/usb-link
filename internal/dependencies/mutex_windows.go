//go:build windows && amd64

package dependencies

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A pre-existing named object must have the same administrative ownership and
// exact two-entry access policy; never repair an unproven object's descriptor.
func verifyDependencyMutex(h windows.Handle) error {
	fail := errors.New("DEPENDENCY_MUTEX_UNPROVEN")
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fail
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !(owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return fail
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return fail
	}
	seen := map[string]bool{}
	for i := uint32(0); i < 2; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Header.AceSize < 16 || ace.Header.AceSize > 68 || ace.Mask != 0x001f0001 {
			return fail
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		count := *(*byte)(unsafe.Add(unsafe.Pointer(sid), 1))
		if uint32(ace.Header.AceSize) != 16+4*uint32(count) || !sid.IsValid() || !(sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid)) || seen[sid.String()] {
			return fail
		}
		seen[sid.String()] = true
	}
	return nil
}
