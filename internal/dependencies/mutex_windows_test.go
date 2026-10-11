//go:build windows && amd64

package dependencies

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDependencyMutexExistingHandleAndUnprovenObject(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an interactive elevated Windows token")
	}
	for _, trusted := range []bool{true, false} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			policy := "O:BAG:BAD:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)"
			if !trusted {
				policy = "O:BAG:BAD:P(A;;GA;;;WD)"
			}
			sd, err := windows.SecurityDescriptorFromString(policy)
			if err != nil {
				t.Fatal(err)
			}
			name := windows.StringToUTF16Ptr(fmt.Sprintf(`Global\USBLinkDependencyFixture-%d-%d`, os.Getpid(), time.Now().UnixNano()))
			sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
			first, err := windows.CreateMutex(sa, false, name)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(first)
			second, err := windows.CreateMutex(sa, false, name)
			if err != nil && err != windows.ERROR_ALREADY_EXISTS {
				t.Fatal(err)
			}
			defer windows.CloseHandle(second)
			if err := verifyDependencyMutex(second); (err == nil) != trusted {
				t.Fatalf("existing mutex trust=%t: %v", trusted, err)
			}
			if trusted {
				state, err := windows.WaitForSingleObject(second, 1000)
				if err != nil || state != windows.WAIT_OBJECT_0 {
					t.Fatal(state, err)
				}
				if err := windows.ReleaseMutex(second); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
