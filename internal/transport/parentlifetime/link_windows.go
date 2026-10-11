//go:build windows && amd64

// Package parentlifetime binds an owned child to its actual kernel parent.
// It observes only process exit; it cannot terminate or adopt a process.
package parentlifetime

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

type Link struct {
	Handle   windows.Handle
	PID      uint32
	Creation uint64
}

// Prepare opens only this process with read/synchronize access. The caller
// passes this inheritable handle through Go's explicit inherited-handle list.
func Prepare() (Link, error) {
	l := Link{PID: windows.GetCurrentProcessId()}
	h, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, true, l.PID)
	if e != nil {
		return Link{}, errors.New("USB_PARENT_HANDLE_UNAVAILABLE")
	}
	l.Handle = h
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		windows.CloseHandle(h)
		return Link{}, errors.New("USB_PARENT_CREATION_UNAVAILABLE")
	}
	l.Creation = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	return l, nil
}

func (l Link) Close() {
	if l.Handle != 0 {
		windows.CloseHandle(l.Handle)
	}
}

// Validate never opens the supplied PID. The inherited exact handle must name
// the actual kernel parent, with the same creation time, preventing PID reuse.
func (l Link) Validate() error {
	if l.Handle == 0 || l.Handle == windows.InvalidHandle || l.PID == 0 || l.Creation == 0 {
		return errors.New("USB_PARENT_LINK_INVALID")
	}
	pid, e := windows.GetProcessId(l.Handle)
	if e != nil || pid != l.PID {
		return errors.New("USB_PARENT_HANDLE_IDENTITY_CHANGED")
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(l.Handle, &created, &exited, &kernel, &user) != nil || uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) != l.Creation {
		return errors.New("USB_PARENT_CREATION_CHANGED")
	}
	self, e := windows.GetCurrentProcess()
	if e != nil {
		return errors.New("USB_PARENT_KERNEL_IDENTITY_UNAVAILABLE")
	}
	var basic windows.PROCESS_BASIC_INFORMATION
	var size uint32
	if windows.NtQueryInformationProcess(self, 0, unsafe.Pointer(&basic), uint32(unsafe.Sizeof(basic)), &size) != nil || size != uint32(unsafe.Sizeof(basic)) || basic.InheritedFromUniqueProcessId != uintptr(l.PID) {
		return errors.New("USB_PARENT_KERNEL_IDENTITY_CHANGED")
	}
	return nil
}

// Watch joins the context callback before closing its private wake event. A
// normal stop or parent exit cancels this child's existing graceful cleanup.
// No timer is needed and no handle to an unrelated process is opened.
func (l Link) Watch(ctx context.Context, cancel context.CancelFunc, stop windows.Handle) (func(), error) {
	if ctx == nil || cancel == nil || stop == 0 || l.Validate() != nil {
		return nil, errors.New("USB_PARENT_MONITOR_UNPROVEN")
	}
	wake, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return nil, errors.New("USB_PARENT_WAKE_UNAVAILABLE")
	}
	return watch(ctx, cancel, func() { windows.SetEvent(wake) }, func() bool {
		state, err := windows.WaitForMultipleObjects([]windows.Handle{stop, l.Handle, wake}, false, windows.INFINITE)
		return err != nil || state != windows.WAIT_OBJECT_0+2
	}, func() { windows.CloseHandle(wake) }), nil
}
