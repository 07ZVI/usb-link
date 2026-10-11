//go:build windows && amd64

package winusb

import (
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"time"
	"unsafe"
)

type Read struct {
	Buffer     []byte
	Overlapped windows.Overlapped
	pending    bool
	pin        runtime.Pinner
}

func NewRead(size int) (*Read, error) {
	event, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return nil, e
	}
	r := &Read{Buffer: make([]byte, size), Overlapped: windows.Overlapped{HEvent: event}}
	r.pin.Pin(&r.Buffer[0])
	r.pin.Pin(&r.Overlapped)
	return r, nil
}
func (i *Interface) Submit(r *Read, pipe byte) error {
	if r.pending {
		return fmt.Errorf("read already pending")
	}
	windows.ResetEvent(r.Overlapped.HEvent)
	r.Overlapped.Internal = 0
	r.Overlapped.InternalHigh = 0
	e := boolCall("WinUsb_ReadPipe", i.Handle, uintptr(pipe), uintptr(unsafe.Pointer(&r.Buffer[0])), uintptr(len(r.Buffer)), 0, uintptr(unsafe.Pointer(&r.Overlapped)))
	if e != nil && !isPending(e) {
		return e
	}
	r.pending = true
	return nil
}
func isPending(e error) bool { // API errors are wrapped with the function name.
	for e != nil {
		if e == windows.ERROR_IO_PENDING {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return false
}
func (i *Interface) Result(r *Read, wait bool) ([]byte, error) {
	var n uint32
	var w uintptr
	if wait {
		w = 1
	}
	e := windows.GetOverlappedResult(i.File, &r.Overlapped, &n, w != 0)
	if e != nil {
		return nil, e
	}
	r.pending = false
	if n > uint32(len(r.Buffer)) {
		return nil, fmt.Errorf("read length overflow")
	}
	return r.Buffer[:n], nil
}
func (r *Read) Ready(ms uint32) (bool, error) {
	v, e := windows.WaitForSingleObject(r.Overlapped.HEvent, ms)
	if e != nil {
		return false, e
	}
	if v == windows.WAIT_OBJECT_0 {
		return true, nil
	}
	if v == uint32(windows.WAIT_TIMEOUT) {
		return false, nil
	}
	return false, fmt.Errorf("wait result=%d", v)
}

// Drain cancellation before unpinning buffers or freeing WinUSB handles.
func (i *Interface) CloseReads(rs []*Read) {
	for _, r := range rs {
		if r.pending {
			windows.CancelIoEx(i.File, &r.Overlapped)
		}
	}
	for _, r := range rs {
		if r.pending {
			var n uint32
			windows.GetOverlappedResult(i.File, &r.Overlapped, &n, true)
			r.pending = false
		}
		windows.CloseHandle(r.Overlapped.HEvent)
		r.pin.Unpin()
	}
}
func (i *Interface) Write(pipe byte, b []byte, timeout time.Duration) error {
	if len(b) == 0 {
		return fmt.Errorf("empty write")
	}
	event, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(event)
	ov := &windows.Overlapped{HEvent: event}
	var pin runtime.Pinner
	pin.Pin(ov)
	pin.Pin(&b[0])
	defer pin.Unpin()
	var n uint32
	e = boolCall("WinUsb_WritePipe", i.Handle, uintptr(pipe), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, uintptr(unsafe.Pointer(ov)))
	if e != nil && !isPending(e) {
		return e
	}
	v, waitErr := windows.WaitForSingleObject(event, uint32(timeout/time.Millisecond))
	if waitErr != nil || v != windows.WAIT_OBJECT_0 {
		windows.CancelIoEx(i.File, ov)
		windows.GetOverlappedResult(i.File, ov, &n, true)
		return fmt.Errorf("write wait failed/timeout: status=%d error=%v", v, waitErr)
	}
	e = windows.GetOverlappedResult(i.File, ov, &n, false)
	if e != nil {
		return e
	}
	if int(n) != len(b) {
		return fmt.Errorf("short write %d/%d", n, len(b))
	}
	return nil
}
