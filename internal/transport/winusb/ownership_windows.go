//go:build windows && amd64

package winusb

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

func OwnRuntime() (func(), error) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	// Legacy mutex name, kept for compatibility with installed versions.
	name, _ := windows.UTF16PtrFromString(`Global\SuhangUSBBridgeRuntime`)
	h, err := windows.CreateMutex(&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, false, name)
	if err != nil {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return nil, fmt.Errorf("USB bridge runtime already active or inaccessible: %w", err)
	}
	return func() { windows.CloseHandle(h) }, nil
}
