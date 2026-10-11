//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func nativeMutexFixture(t *testing.T, descriptor string) (string, windows.Handle) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("native mutex integration requires elevated test process; this is not a native PASS")
	}
	name := fmt.Sprintf(`Local\USBLinkSignedUpgradeJob-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateMutex(&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, false, windows.StringToUTF16Ptr(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	return name, h
}

func TestUpgradeMutexNativeCreateValidateAcquireRelease(t *testing.T) {
	for _, sddl := range []string{upgradeJobMutexSDDL, "D:P(A;;GA;;;SY)(A;;GA;;;BA)"} {
		t.Run(sddl, func(t *testing.T) {
			name, h := nativeMutexFixture(t, sddl)
			actual, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			control, _, err := actual.Control()
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := actual.DACL()
			if err != nil || dacl == nil {
				t.Fatalf("DACL: %v", err)
			}
			for i := uint32(0); i < uint32(dacl.AceCount); i++ {
				var ace *windows.ACCESS_ALLOWED_ACE
				if err := windows.GetAce(dacl, i, &ace); err != nil {
					t.Fatal(err)
				}
				t.Logf("native descriptor control=0x%04x protected=%t ACE%d mask=0x%08x flags=0x%02x", control, control&windows.SE_DACL_PROTECTED != 0, i, ace.Mask, ace.Header.AceFlags)
			}
			if err := mutexDescriptorPolicy(actual); err != nil {
				t.Fatal(err)
			}
			legacy, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("legacy file-ACL comparator accepted native mutex=%t", sameACL(actual, legacy))
			unlock, err := acquireUpgradeJobMutex(name, 5000)
			if err != nil {
				t.Fatal(err)
			}
			// A callback dispatched on another OS thread cannot release the owner.
			wrong := make(chan error, 1)
			go func() { wrong <- unlock() }()
			if err := <-wrong; err == nil || !strings.Contains(err.Error(), "release_thread_changed") {
				t.Fatalf("foreign callback: %v", err)
			}
			// A contending writer must remain excluded while the owner is pinned.
			blocked := make(chan error, 1)
			go func() {
				u, err := acquireUpgradeJobMutex(name, 20)
				if err == nil {
					_ = u()
					err = fmt.Errorf("writer entered while mutex held")
				}
				blocked <- err
			}()
			if err := <-blocked; err == nil || !strings.Contains(err.Error(), "reason=wait status=0x00000102") {
				t.Fatalf("contending writer: %v", err)
			}
			if err := unlock(); err != nil {
				t.Fatal(err)
			}
			// Following release a new goroutine must acquire and release normally.
			next := make(chan error, 1)
			go func() {
				u, err := acquireUpgradeJobMutex(name, 5000)
				if err == nil {
					err = u()
				}
				next <- err
			}()
			if err := <-next; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUpgradeMutexNativeRejectExistingExtraACEWithoutMutation(t *testing.T) {
	name, h := nativeMutexFixture(t, "D:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)(A;;0x00100000;;;BU)")
	before, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireUpgradeJobMutex(name, 20); err == nil || !strings.Contains(err.Error(), "reason=ace_count") {
		t.Fatalf("unexpected security result: %v", err)
	}
	after, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatal("rejected existing object was modified")
	}
}

func TestUpgradeMutexNativeAbandonedOwnerCanRecover(t *testing.T) {
	name, h := nativeMutexFixture(t, upgradeJobMutexSDDL)
	ready := make(chan error, 1)
	go func() {
		// Deliberately return while locked to this OS thread. Go terminates
		// that thread; Windows marks its owned mutex abandoned, as after crash.
		runtime.LockOSThread()
		status, err := windows.WaitForSingleObject(h, 5000)
		if err == nil && status != windows.WAIT_OBJECT_0 {
			err = fmt.Errorf("fixture wait status=0x%08x", status)
		}
		ready <- err
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	// Do not infer release from goroutine completion: the native wait must
	// observe ownership transfer after thread termination.
	u, err := acquireUpgradeJobMutex(name, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if err := u(); err != nil {
		t.Fatal(err)
	}
}
