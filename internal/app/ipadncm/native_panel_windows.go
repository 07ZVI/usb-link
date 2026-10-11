//go:build windows && amd64

package ipadncm

import (
	"context"
	"golang.org/x/sys/windows"
	"runtime"
	"sync"
	"unsafe"
)

type PanelCheck struct {
	Text              string
	Checked, Disabled bool
}
type nativePanel struct {
	ctx      context.Context
	hwnd     uintptr
	checks   []uintptr
	values   []bool
	disabled []bool
	accepted bool
	closed   bool
}

var panelExclusive sync.Mutex
var nativePanels = struct {
	sync.Mutex
	m map[uintptr]*nativePanel
}{m: map[uintptr]*nativePanel{}}
var panelCallback = windows.NewCallback(func(hwnd uintptr, msg uint32, wp, lp uintptr) uintptr {
	nativePanels.Lock()
	p := nativePanels.m[hwnd]
	nativePanels.Unlock()
	if p != nil {
		if msg == 0x113 && p.ctx.Err() != nil {
			p.closed = true
			appUser.NewProc("DestroyWindow").Call(hwnd)
			return 0
		}
		if msg == 0x2 {
			appUser.NewProc("KillTimer").Call(hwnd, 1)
			return 0
		}
		if msg == 0x10 {
			p.closed = true
			appUser.NewProc("DestroyWindow").Call(hwnd)
			return 0
		}
		if msg == 0x111 && wp>>16 == 0 {
			if uint16(wp) == 1 || uint16(wp) == 2 {
				p.accepted = uint16(wp) == 1
				if p.accepted {
					for i, h := range p.checks {
						v, _, _ := appUser.NewProc("SendMessageW").Call(h, 0xf0, 0, 0)
						p.values[i] = v == 1 && !p.disabled[i]
					}
				}
				p.closed = true
				appUser.NewProc("DestroyWindow").Call(hwnd)
				return 0
			}
		}
	}
	v, _, _ := appUser.NewProc("DefWindowProcW").Call(hwnd, uintptr(msg), wp, lp)
	return v
})

// Modal native controls; cancellation/default focus deny. No browser, network
// IPC, web runtime, or unchecked text is passed to a system shell.
func NativePanel(title, body, accept string, checks []PanelCheck) (bool, []bool) {
	return NativePanelWithContext(connectionContext(), title, body, accept, checks)
}
func NativePanelWithContext(ctx context.Context, title, body, accept string, checks []PanelCheck) (bool, []bool) {
	if relay := currentPanelRelay(); relay != nil {
		if ctx.Err() != nil {
			return false, nil
		}
		return relay(ctx, title, body, accept, checks)
	}
	panelExclusive.Lock()
	defer panelExclusive.Unlock()
	if ctx.Err() != nil {
		return false, nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	class, _ := windows.UTF16PtrFromString("SuhangConnectionPanel052")
	instance, _, _ := appKernel.NewProc("GetModuleHandleW").Call(0)
	cursor, _, _ := appUser.NewProc("LoadCursorW").Call(0, 32512)
	wc := appWindowClass{Size: 80, Procedure: panelCallback, Instance: instance, Cursor: cursor, Background: 6, Class: class}
	atom, _, _ := appUser.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return false, nil
	}
	defer appUser.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(class)), instance)
	dpi := uintptr(96)
	if fn := appUser.NewProc("GetDpiForSystem"); fn.Find() == nil {
		v, _, _ := fn.Call()
		if v >= 96 && v <= 384 {
			dpi = v
		}
	}
	d := func(n int) uintptr { return uintptr(n) * dpi / 96 }
	text, _ := windows.UTF16PtrFromString(title)
	sw, _, _ := appUser.NewProc("GetSystemMetrics").Call(0)
	sh, _, _ := appUser.NewProc("GetSystemMetrics").Call(1)
	dpi = min(dpi, max(uintptr(48), (sw-32)*96/680), max(uintptr(48), (sh-70)*96/uintptr(500+len(checks)*38)))
	width, height := d(680), d(500+len(checks)*38)
	hwnd, _, _ := appUser.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(text)), 0xc80000, (sw-min(width, sw))/2, (sh-min(height, sh))/2, min(width, sw), min(height, sh), 0, 0, instance, 0)
	if hwnd == 0 {
		return false, nil
	}
	defer appUser.NewProc("DestroyWindow").Call(hwnd)
	var client appWindowRect
	appUser.NewProc("GetClientRect").Call(hwnd, uintptr(unsafe.Pointer(&client)))
	dpi = min(dpi, max(uintptr(48), uintptr(client.Right)*96/664), max(uintptr(48), uintptr(client.Bottom)*96/uintptr(448+len(checks)*38)))
	p := &nativePanel{ctx: ctx, hwnd: hwnd, values: make([]bool, len(checks)), disabled: make([]bool, len(checks))}
	nativePanels.Lock()
	nativePanels.m[hwnd] = p
	nativePanels.Unlock()
	defer func() { nativePanels.Lock(); delete(nativePanels.m, hwnd); nativePanels.Unlock() }()
	var fonts []uintptr
	defer func() {
		appUser.NewProc("DestroyWindow").Call(hwnd)
		for _, f := range fonts {
			appGDI.NewProc("DeleteObject").Call(f)
		}
	}()
	font := func(size, weight int) uintptr {
		face, _ := windows.UTF16PtrFromString("Segoe UI")
		f, _, _ := appGDI.NewProc("CreateFontW").Call(uintptr(uint32(int32(-int(d(size))))), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face)))
		if f != 0 {
			fonts = append(fonts, f)
		}
		return f
	}
	normal, header := font(16, 400), font(25, 600)
	child := func(kind, s string, style uintptr, x, y, w, h, id int, f uintptr) uintptr {
		k, _ := windows.UTF16PtrFromString(kind)
		t, _ := windows.UTF16PtrFromString(s)
		v, _, _ := appUser.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(k)), uintptr(unsafe.Pointer(t)), 0x50000000|style, d(x), d(y), d(w), d(h), hwnd, uintptr(id), instance, 0)
		if v != 0 {
			appUser.NewProc("SendMessageW").Call(v, 0x30, f, 1)
		}
		return v
	}
	if child("STATIC", title, 0, 28, 24, 620, 40, 0, header) == 0 {
		return false, nil
	}
	if child("EDIT", body, 0x4|0x40|0x800|0x00200000, 28, 80, 620, 260, 0, normal) == 0 {
		return false, nil
	}
	for i, c := range checks {
		p.disabled[i] = c.Disabled
		h := child("BUTTON", c.Text, 0x3|0x10000, 28, 354+i*38, 620, 30, 100+i, normal)
		if h == 0 {
			return false, nil
		}
		if c.Checked {
			appUser.NewProc("SendMessageW").Call(h, 0xf1, 1, 0)
		}
		if c.Disabled {
			appUser.NewProc("EnableWindow").Call(h, 0)
		}
		p.checks = append(p.checks, h)
	}
	yes := child("BUTTON", accept, 0x10000, 365, 394+len(checks)*38, 140, 38, 1, normal)
	no := child("BUTTON", "取消", 0x10000|1, 515, 394+len(checks)*38, 130, 38, 2, normal)
	if yes == 0 || no == 0 {
		return false, nil
	}
	appUser.NewProc("SetTimer").Call(hwnd, 1, 500, 0)
	appUser.NewProc("ShowWindow").Call(hwnd, 1)
	appUser.NewProc("SetForegroundWindow").Call(hwnd)
	appUser.NewProc("SetFocus").Call(no)
	var msg appWindowMessage
	for !p.closed {
		r, _, _ := appUser.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			if r == 0 {
				appUser.NewProc("PostQuitMessage").Call(msg.WParam)
			}
			return false, nil
		}

		handled, _, _ := appUser.NewProc("IsDialogMessageW").Call(hwnd, uintptr(unsafe.Pointer(&msg)))
		if handled == 0 {
			appUser.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg)))
			appUser.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg)))
		}
	}
	return p.accepted, p.values
}
