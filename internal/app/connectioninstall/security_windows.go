//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
	"unsafe"
)

// SecurityDirectory holds host policy intent/receipts. Normal USB cleanup does
// not remove it. Its ACL excludes writes and reads by standard users.
func SecurityDirectory() (string, error) {
	root, err := StateDirectory()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "security")
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return "", err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err = windows.CreateDirectory(windows.StringToUTF16Ptr(dir), &sa); err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return "", err
	}
	if err = noReparse(dir); err != nil {
		return "", err
	}
	actual, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || !sameACL(actual, sd) {
		return "", fmt.Errorf("SECURITY_STORE_ACL_CHANGED")
	}
	return dir, nil
}
