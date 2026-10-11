//go:build windows && amd64

package interfaceconfig

import (
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// The bridge and parent share one originals file. A process-local mutex is not
// enough; serialize the durable transaction across both while pinning the OS
// thread that owns this native mutex. Existing objects are verified, not re-ACL'd.
func lockConfig() (func(), error) {
	configMu.Lock()
	runtime.LockOSThread()
	fail := func() (func(), error) {
		runtime.UnlockOSThread()
		configMu.Unlock()
		return nil, errors.New("USB_INTERFACE_CONFIG_LEASE_UNPROVEN")
	}
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)")
	if e != nil {
		return fail()
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateMutexEx(&sa, windows.StringToUTF16Ptr(`Global\USBLinkInterfaceConfig-v1`), 0, 0x00120001)
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return fail()
	}
	actual, e := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || !configACLMatches(actual, sd) {
		windows.CloseHandle(h)
		return fail()
	}
	code, e := windows.WaitForSingleObject(h, 30000)
	if e != nil || (code != windows.WAIT_OBJECT_0 && code != 0x80) {
		windows.CloseHandle(h)
		return fail()
	}
	return func() { windows.ReleaseMutex(h); windows.CloseHandle(h); runtime.UnlockOSThread(); configMu.Unlock() }, nil
}
