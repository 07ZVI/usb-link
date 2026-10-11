//go:build windows && amd64

package dependencies

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

var user32 = windows.NewLazySystemDLL("user32.dll")

// WithProgress needs no CLR. Closing the window cancels downloads; official
// installers already running finish their own transaction and license UI.
func WithProgress(ctx context.Context, work func(context.Context) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	create := user32.NewProc("CreateWindowExW")
	class := windows.StringToUTF16Ptr("STATIC")
	title := windows.StringToUTF16Ptr("USB Link · 必备组件")
	h, _, _ := create.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)), 0x10cf0000, 200, 200, 620, 180, 0, 0, 0, 0)
	if h == 0 {
		return work(ctx)
	}
	defer user32.NewProc("DestroyWindow").Call(h)
	text, _, _ := create.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("正在检查必备组件…"))), 0x50000000, 18, 18, 560, 100, h, 0, 0, 0)
	var latest atomic.Value
	latest.Store("正在检查必备组件…")
	unsubscribe := Default.ObserveProgress(func(s Status) {
		latest.Store(fmt.Sprintf("%s %s · %s\n%s\n%s", s.ID, s.Version, fmt.Sprintf("%s (%d / %d bytes)", s.State, s.Bytes, s.Total), joinFeatures(s.Features), s.Problem))
	})
	defer unsubscribe()
	old, _, _ := user32.NewProc("GetWindowLongPtrW").Call(h, ^uintptr(3))
	callback := windows.NewCallback(func(hwnd uintptr, msg uint32, w, l uintptr) uintptr {
		if msg == 0x10 {
			cancel()
			return 0
		}
		result, _, _ := user32.NewProc("CallWindowProcW").Call(old, hwnd, uintptr(msg), w, l)
		return result
	})
	user32.NewProc("SetWindowLongPtrW").Call(h, ^uintptr(3), callback)
	done := make(chan error, 1)
	go func() { done <- work(ctx) }()
	type message struct {
		Window  uintptr
		ID      uint32
		W, L    uintptr
		Time    uint32
		X, Y    int32
		Private uint32
	}
	var msg message
	for {
		select {
		case e := <-done:
			return e
		default:
		}
		label := windows.StringToUTF16Ptr(latest.Load().(string))
		user32.NewProc("SetWindowTextW").Call(text, uintptr(unsafe.Pointer(label)))
		for {
			ok, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
			if ok == 0 {
				break
			}
			user32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg)))
			user32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg)))
		}
		time.Sleep(40 * time.Millisecond)
	}
}
func joinFeatures(features []string) string {
	result := "影响功能："
	for i, f := range features {
		if i > 0 {
			result += "、"
		}
		result += f
	}
	return result
}
