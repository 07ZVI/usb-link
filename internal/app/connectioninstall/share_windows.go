//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
	"unsafe"
)

// A dedicated child of the protected product root. Its parent cannot be
// replaced by a standard user; only the installing account gets Modify access.
// It is user data, deliberately preserved by version cleanup and uninstall.
func SharedDirectory() (string, error) {
	root, e := dataRoot("Shared Files")
	if e != nil {
		return "", e
	}
	ownerSID, e := sharedDirectoryOwnerSID()
	if e != nil {
		return "", e
	}
	acl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + ownerSID + ")"
	sd, e := windows.SecurityDescriptorFromString(acl)
	if e != nil {
		return "", e
	}
	dir := filepath.Join(root, "Shared Files")
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	e = windows.CreateDirectory(windows.StringToUTF16Ptr(dir), &sa)
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return "", e
	}
	if e = noReparse(dir); e != nil {
		return "", e
	}
	actual, e := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil || !sameACL(actual, sd) && !ownedSMBDefaultDACL(dir, actual, sd) {
		return "", fmt.Errorf("shared directory permissions do not match this account")
	}
	return dir, nil
}
