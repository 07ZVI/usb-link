//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

const upgradeJobMutexName = `Global\USBLinkSignedUpgradeJob-v2`
const upgradeJobMutexSDDL = "D:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)"

func mutexDescriptorPolicy(sd *windows.SECURITY_DESCRIPTOR) error {
	if sd == nil {
		return fmt.Errorf("reason=descriptor_missing")
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("reason=control_query: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return fmt.Errorf("reason=owner_query control=0x%04x: %v", control, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("reason=process_user_query: %w", err)
	}
	// Service and updater run in Session0 while the migration bootstrap runs in
	// the user's session. Only the protected, SCM-verified owner binding can
	// identify that same user as a legitimate existing Global mutex owner.
	var boundOwner *windows.SID
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		if binding, e := CurrentCoreBinding(); e == nil {
			boundOwner, _ = windows.StringToSid(binding.OwnerSID)
		}
	}
	principal := func(sid *windows.SID) string {
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			return "system"
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			return "administrators"
		case windows.EqualSid(sid, user.User.Sid) || boundOwner != nil && windows.EqualSid(sid, boundOwner):
			return "process_user"
		default:
			return "other"
		}
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("reason=dacl_null_or_missing control=0x%04x: %v", control, err)
	}
	if dacl.AceCount != 2 {
		return fmt.Errorf("reason=ace_count control=0x%04x actual=%d expected=2", control, dacl.AceCount)
	}
	entries := make([]mutexACE, 0, 2)
	for i := uint32(0); i < 2; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return fmt.Errorf("reason=ace_query control=0x%04x index=%d: %v", control, i, err)
		}
		// SID is variable length. Validate its bounds before calling SID APIs;
		// an object/callback/unknown ACE cannot be interpreted as an allow ACE.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Header.AceSize < 16 || ace.Header.AceSize > 68 {
			return fmt.Errorf("reason=ace_type_or_inheritance control=0x%04x index=%d type=%d flags=0x%02x size=%d", control, i, ace.Header.AceType, ace.Header.AceFlags, ace.Header.AceSize)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		// SID has an 8-byte header and one 4-byte element per subauthority.
		count := *(*byte)(unsafe.Add(unsafe.Pointer(sid), 1))
		if uint32(ace.Header.AceSize) != 16+4*uint32(count) || !sid.IsValid() {
			return fmt.Errorf("reason=ace_sid_shape control=0x%04x index=%d", control, i)
		}
		entries = append(entries, mutexACE{Type: ace.Header.AceType, Flags: ace.Header.AceFlags, Mask: uint32(ace.Mask), Principal: principal(sid)})
	}
	if err := validateMutexPolicy(principal(owner), true, entries); err != nil {
		return fmt.Errorf("%w control=0x%04x protected=%t", err, control, control&windows.SE_DACL_PROTECTED != 0)
	}
	return nil
}

func upgradeJobLock() (func() error, error) {
	return acquireUpgradeJobMutex(upgradeJobMutexName, 5000)
}

// The name argument exists only for isolated native tests. Production always
// uses the fixed name above; existing objects are checked, never re-ACL'd.
func acquireUpgradeJobMutex(name string, timeout uint32) (func() error, error) {
	runtime.LockOSThread()
	thread := windows.GetCurrentThreadId()
	sd, err := windows.SecurityDescriptorFromString(upgradeJobMutexSDDL)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("upgrade mutex reason=sddl: %w", err)
	}
	h, err := windows.CreateMutex(&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, false, windows.StringToUTF16Ptr(name))
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("upgrade mutex reason=create: %w", err)
	}
	fail := func(cause error) (func() error, error) {
		closeErr := windows.CloseHandle(h)
		runtime.UnlockOSThread()
		return nil, errors.Join(cause, closeErr)
	}
	actual, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fail(fmt.Errorf("upgrade mutex reason=security_query: %w", err))
	}
	if err := mutexDescriptorPolicy(actual); err != nil {
		return fail(fmt.Errorf("upgrade mutex security rejected: %w", err))
	}
	status, err := windows.WaitForSingleObject(h, timeout)
	if err != nil || status != windows.WAIT_OBJECT_0 && status != 0x80 {
		return fail(fmt.Errorf("upgrade mutex reason=wait status=0x%08x: %v", status, err))
	}
	var released atomic.Bool
	return func() error {
		// Mutex ownership is OS-thread scoped. Neither an HTTP callback nor a
		// later goroutine may release this owner's lock or unpin its thread.
		if windows.GetCurrentThreadId() != thread {
			return fmt.Errorf("upgrade mutex reason=release_thread_changed")
		}
		if !released.CompareAndSwap(false, true) {
			return fmt.Errorf("upgrade mutex reason=duplicate_release")
		}
		releaseErr := windows.ReleaseMutex(h)
		closeErr := windows.CloseHandle(h)
		runtime.UnlockOSThread()
		if err := errors.Join(releaseErr, closeErr); err != nil {
			return fmt.Errorf("upgrade mutex reason=release: %w", err)
		}
		return nil
	}, nil
}
