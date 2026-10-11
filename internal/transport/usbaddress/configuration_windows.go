//go:build windows && amd64

package usbaddress

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// Serialize address planning across the parent and bridge processes. The
// snapshot and conflict check must not race another device's address creation.
func ConfigurationLock(ctx context.Context) (func(), error) {
	runtime.LockOSThread()
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if e != nil {
		runtime.UnlockOSThread()
		return nil, e
	}
	h, e := windows.CreateMutex(&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, false, windows.StringToUTF16Ptr(`Local\USBLinkTopologyConfiguration-v1`))
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		if h != 0 {
			windows.CloseHandle(h)
		}
		runtime.UnlockOSThread()
		return nil, e
	}
	deadline := time.Now().Add(90 * time.Second)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		status, err := windows.WaitForSingleObject(h, 100)
		if err != nil {
			windows.CloseHandle(h)
			runtime.UnlockOSThread()
			return nil, err
		}
		if status == windows.WAIT_OBJECT_0 || status == 0x80 {
			var once sync.Once
			return func() { once.Do(func() { windows.ReleaseMutex(h); windows.CloseHandle(h); runtime.UnlockOSThread() }) }, nil
		}
	}
	windows.CloseHandle(h)
	runtime.UnlockOSThread()
	return nil, fmt.Errorf("USB_TOPOLOGY_CONFIGURATION_BUSY")
}
