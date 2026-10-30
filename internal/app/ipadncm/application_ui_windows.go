//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

var appUser = windows.NewLazySystemDLL("user32.dll")
var appKernel = windows.NewLazySystemDLL("kernel32.dll")
var appGDI = windows.NewLazySystemDLL("gdi32.dll")

// SDK layouts for amd64 WNDCLASSEXW and MSG, including MSG's trailing private DWORD.
type appWindowClass struct {
	Size, Style                        uint32
	Procedure                          uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Class                        *uint16
	SmallIcon                          uintptr
}
type appWindowMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	X, Y           int32
	Private        uint32
}
type appWindowRect struct{ Left, Top, Right, Bottom int32 }
type appWindow struct {
	modern                                                                                                      *modernUI
	ctx                                                                                                         context.Context
	cancel                                                                                                      context.CancelFunc
	state                                                                                                       *applicationState
	hwnd, title, ip, details, copy, stream, retry, stop, notice, font, headingFont, valueFont, settings, tx, rx uintptr
	scale                                                                                                       int
	lastTitle, lastIP, lastDetail                                                                               string
	tray                                                                                                        bool
	trayTip                                                                                                     string
	taskbarCreated                                                                                              uint32
	stopping                                                                                                    bool
	trayAck                                                                                                     *trayRemovalAck
	trayRemoved                                                                                                 bool
}

var appWindows = struct {
	sync.Mutex
	byHandle map[uintptr]*appWindow
}{byHandle: make(map[uintptr]*appWindow)}
var appWindowProc = windows.NewCallback(func(hwnd uintptr, message uint32, wparam, lparam uintptr) uintptr {
	appWindows.Lock()
	w := appWindows.byHandle[hwnd]
	appWindows.Unlock()
	if w != nil {
		if w.taskbarCreated != 0 && message == w.taskbarCreated {
			w.tray = false
			w.addTray()
			return 0
		}
		switch message {
		case 0x219: // WM_DEVICECHANGE: signal cache inspection, never start USB work here.
			signalConnectionChanged(uint32(wparam))
			return 0
		case 0x138, 0x133: // Native static/read-only edit colors.
			color, _, _ := appUser.NewProc("GetSysColor").Call(5)
			appGDI.NewProc("SetBkColor").Call(wparam, color)
			appGDI.NewProc("SetTextColor").Call(wparam, 0x41342a)
			brush, _, _ := appUser.NewProc("GetSysColorBrush").Call(5)
			return brush
		case 0x5: // WM_SIZE
			w.layout()
			return 0
		case 0x113: // WM_TIMER
			w.refresh()
			return 0
		case 0x111: // WM_COMMAND: buttons only, BN_CLICKED only.
			if wparam>>16 != 0 || w.stopping || w.ctx.Err() != nil {
				return 0
			}
			switch uint16(wparam) {
			case 104:
				if w.modern != nil && w.modern.show("native-command") {
					return 0
				}
				appUser.NewProc("ShowWindow").Call(hwnd, 9)
				appUser.NewProc("SetForegroundWindow").Call(hwnd)
			case 100:
				ip := w.state.snapshot().WindowsIPv4
				if ip != "" && copyApplicationIP(hwnd, ip) {
					appSetText(w.notice, "已複製電腦 IP 到 Windows 剪貼簿")
				} else {
					appSetText(w.notice, "複製未完成；可選取上方地址，按 Ctrl+C")
				}
			case 101:
				w.stopSession()
			case 103:
				if w.state.Settings != nil {
					w.state.Settings()
				}
			case 102:
				w.state.update(func(r *ApplicationResult) { r.UserReportsStream = true })
				appSetText(w.notice, "已記錄你的體驗；這項回報不代表獨立串流驗證。")
				w.refresh()
			case 105:
				if proxy := currentServiceUIProxy(); proxy != nil {
					go func() { _, _ = proxy.Action(w.ctx, []byte(`{"action":"retry"}`)) }()
					return 0
				}
				if w.state.snapshot().DeviceKind == "Mac" {
					requestMacRetry()
				} else {
					requestConnectionRetry()
				}
			}
			return 0
		case 0x8002: // Shell tray mouse notifications.
			if w.stopping || w.ctx.Err() != nil {
				return 0
			}
			if uint32(lparam) == 0x202 || uint32(lparam) == 0x203 {
				if w.modern != nil && w.modern.show("tray-click") {
					return 0
				}
				appUser.NewProc("ShowWindow").Call(hwnd, 9)
				appUser.NewProc("SetForegroundWindow").Call(hwnd)
			}
			if uint32(lparam) == 0x205 {
				w.trayMenu()
			}
			return 0
		case 0x10: // Close keeps the owned monitor alive; explicit End exits.
			show := uintptr(2)
			if w.tray {
				show = 0
			}
			appUser.NewProc("ShowWindow").Call(hwnd, show)
			return 0
		case 0x8003: // Exit state changed: refresh the tray tooltip.
			if currentExitTip.Load() {
				w.setTrayTip(trayExitTip)
			} else {
				w.setTrayTip(trayTip)
			}
			return 0
		case 0x8005: // Installer-requested close: end now, no exit-program protocol.
			// The verified installer stops the core, which restores on its own.
			// Cancelling here also keeps the core recovery from restarting it.
			w.stopping = true
			w.cancel()
			w.removeTray()
			return 0
		case 0x8004: // Exit path: delete the icon on this thread, then acknowledge.
			w.removeTray()
			return 0
		case 0x8001:
			w.removeTray()
			appUser.NewProc("DestroyWindow").Call(hwnd)
			return 0
		case 0x2: // WM_DESTROY
			w.removeTray()
			appUser.NewProc("KillTimer").Call(hwnd, 1)
			appUser.NewProc("PostQuitMessage").Call(0)
			return 0
		}
	}
	v, _, _ := appUser.NewProc("DefWindowProcW").Call(hwnd, uintptr(message), wparam, lparam)
	return v
})

func appSetText(hwnd uintptr, text string) {
	p, _ := windows.UTF16PtrFromString(text)
	appUser.NewProc("SetWindowTextW").Call(hwnd, uintptr(unsafe.Pointer(p)))
}
func (w *appWindow) stopSession() {
	if currentServiceUIProxy() != nil {
		if w.modern != nil && w.modern.show("program-exit") {
			go w.modern.sendEvent(map[string]string{"event": "program-exit-request"})
		} else {
			appSetText(w.notice, "無法開啟退出確認介面；尚未停止後台或確認恢復。請重新開啟連線介面後使用「退出程序」。")
			appUser.NewProc("ShowWindow").Call(w.hwnd, 9)
			appUser.NewProc("SetForegroundWindow").Call(w.hwnd)
		}
		return
	}
	w.stopping = true
	w.cancel()
	appSetText(w.notice, "正在恢復本輪設定，完成後會退出。請勿強制結束。")
	w.refresh()
}
func (w *appWindow) refresh() {
	if w.modern != nil && !backgroundUIBaseline.Load() {
		visible, _, _ := appUser.NewProc("IsWindowVisible").Call(w.hwnd)
		if visible == 0 {
			return
		}
	}

	r := w.state.snapshot()
	peer := "裝置"
	if r.DeviceKind == "iPad" {
		peer = "iPad"
	}
	if r.DeviceKind == "Mac" {
		peer = "Mac"
	}
	appSetText(w.tx, fmt.Sprintf("電腦 → %s\r\n%.1f Mbps", peer, r.ObservedTransmitMbps))
	appSetText(w.rx, fmt.Sprintf("%s → 電腦\r\n%.1f Mbps", peer, r.ObservedReceiveMbps))
	title, ip, detail := applicationView(r, w.stopping || w.ctx.Err() != nil)
	if title != w.lastTitle {
		appSetText(w.title, title)
		w.lastTitle = title
	}
	if ip != w.lastIP {
		appSetText(w.ip, ip)
		w.lastIP = ip
	}
	if detail != w.lastDetail {
		line, _, _ := appUser.NewProc("SendMessageW").Call(w.details, 0xce, 0, 0) // EM_GETFIRSTVISIBLELINE
		appSetText(w.details, detail)
		appUser.NewProc("SendMessageW").Call(w.details, 0xb6, 0, line) // EM_LINESCROLL preserves user's scroll.
		w.lastDetail = detail
	}
	active := uintptr(1)
	if w.stopping || w.ctx.Err() != nil {
		active = 0
	}
	appUser.NewProc("EnableWindow").Call(w.stop, active)
	appUser.NewProc("EnableWindow").Call(w.stream, active)
	appUser.NewProc("EnableWindow").Call(w.settings, active)
	paused := active != 0 && (r.Status == "MONITOR_PAUSED" || r.Status == "MONITOR_RETRYING")
	retryEnabled, showRetry, showStream := uintptr(0), uintptr(0), uintptr(5)
	if paused {
		retryEnabled, showRetry, showStream = 1, 5, 0
	}
	appUser.NewProc("EnableWindow").Call(w.retry, retryEnabled)
	appUser.NewProc("ShowWindow").Call(w.retry, showRetry)
	if r.DeviceKind == "Mac" && !paused {
		showStream = 0
	}
	appUser.NewProc("ShowWindow").Call(w.stream, showStream)
	if r.WindowsIPv4 == "" {
		active = 0
	}
	appUser.NewProc("EnableWindow").Call(w.copy, active)
}
func (w *appWindow) dip(n int) int { return n * w.scale / 96 }
func (w *appWindow) layout() {
	if w.details == 0 {
		return
	}
	var rect appWindowRect
	appUser.NewProc("GetClientRect").Call(w.hwnd, uintptr(unsafe.Pointer(&rect)))
	width, height := int(rect.Right), int(rect.Bottom)
	gap := w.dip(16)
	line := w.dip(30)
	button := w.dip(36)
	move := func(hwnd uintptr, x, y, ww, hh int) {
		appUser.NewProc("MoveWindow").Call(hwnd, uintptr(max(0, x)), uintptr(max(0, y)), uintptr(max(1, ww)), uintptr(max(1, hh)), 1)
	}
	move(w.title, gap, gap, width-2*gap, line+gap)
	move(w.ip, gap, gap+line+gap, width-3*gap-w.dip(140), w.dip(44))
	move(w.copy, width-gap-w.dip(140), gap+line+gap, w.dip(140), w.dip(44))
	cardTop := gap + line + gap + w.dip(60)
	cardW := (width - 3*gap) / 2
	move(w.tx, gap, cardTop, cardW, w.dip(68))
	move(w.rx, gap+cardW+gap, cardTop, cardW, w.dip(68))
	top := cardTop + w.dip(86)
	bottom := height - gap - button - line - w.dip(14)
	move(w.details, gap, top, width-2*gap, bottom-top)
	move(w.notice, gap, bottom+w.dip(6), width-2*gap, line)
	move(w.settings, gap, height-gap-button, w.dip(85), button)
	move(w.stream, gap+w.dip(97), height-gap-button, w.dip(205), button)
	move(w.retry, gap+w.dip(97), height-gap-button, w.dip(205), button)
	move(w.stop, width-gap-w.dip(205), height-gap-button, w.dip(205), button)

}
func copyApplicationIP(hwnd uintptr, text string) bool {
	p, e := windows.UTF16FromString(text)
	if e != nil {
		return false
	}
	opened, _, _ := appUser.NewProc("OpenClipboard").Call(hwnd)
	if opened == 0 {
		return false
	}
	defer appUser.NewProc("CloseClipboard").Call()
	h, _, _ := appKernel.NewProc("GlobalAlloc").Call(2, uintptr(len(p)*2))
	if h == 0 {
		return false
	}
	transferred := false
	defer func() {
		if !transferred {
			appKernel.NewProc("GlobalFree").Call(h)
		}
	}()
	ptr, _, _ := appKernel.NewProc("GlobalLock").Call(h)
	if ptr == 0 {
		return false
	}
	// Win32 provides this owned memory block; never decode an arbitrary packet pointer.
	windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory").Call(ptr, uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)*2))
	runtime.KeepAlive(p)
	appKernel.NewProc("GlobalUnlock").Call(h)
	ok, _, _ := appUser.NewProc("EmptyClipboard").Call()
	if ok == 0 {
		return false
	}
	ok, _, _ = appUser.NewProc("SetClipboardData").Call(13, h)
	transferred = ok != 0
	return transferred
}

func startApplicationUI(ctx context.Context, s *applicationState, cancel context.CancelFunc) (func(), string) {
	type opened struct {
		hwnd uintptr
		err  string
	}
	ready := make(chan opened, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		if unsafe.Sizeof(appWindowClass{}) != 80 || unsafe.Sizeof(appWindowMessage{}) != 48 {
			ready <- opened{err: "STATUS_WINDOW_ABI_INVALID"}
			return
		}
		// Use normal Windows controls and system DPI; no browser or GUI runtime.
		appUser.NewProc("SetProcessDPIAware").Call()
		dpi := uintptr(96)
		if p := appUser.NewProc("GetDpiForSystem"); p.Find() == nil {
			v, _, _ := p.Call()
			if v >= 96 && v <= 384 {
				dpi = v
			}
		}
		swFit, _, _ := appUser.NewProc("GetSystemMetrics").Call(0)
		shFit, _, _ := appUser.NewProc("GetSystemMetrics").Call(1)
		dpi = min(dpi, max(uintptr(48), (swFit-48)*96/860), max(uintptr(48), (shFit-80)*96/680))
		w := &appWindow{ctx: ctx, cancel: cancel, state: s, scale: int(dpi), trayAck: newTrayRemovalAck()}
		instance, _, _ := appKernel.NewProc("GetModuleHandleW").Call(0)
		cursor, _, _ := appUser.NewProc("LoadCursorW").Call(0, 32512)
		// Legacy window class name, kept for compatibility with installed versions.
		class, _ := windows.UTF16PtrFromString("SuhangUSBStatus061")
		wc := appWindowClass{Size: 80, Procedure: appWindowProc, Instance: instance, Cursor: cursor, Background: 6, Class: class}
		atom, _, _ := appUser.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc)))
		if atom == 0 {
			ready <- opened{err: "STATUS_WINDOW_CLASS_FAILED"}
			return
		}
		defer appUser.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(class)), instance)
		title, _ := windows.UTF16PtrFromString("USB Link " + productVersion)
		sw, _, _ := appUser.NewProc("GetSystemMetrics").Call(0)
		sh, _, _ := appUser.NewProc("GetSystemMetrics").Call(1)
		width, height := min(w.dip(860), max(520, int(sw)-60)), min(w.dip(800), max(480, int(sh)-100))
		hwnd, _, _ := appUser.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)), 0xca0000, uintptr(max(0, (int(sw)-width)/2)), uintptr(max(0, (int(sh)-height)/2)), uintptr(width), uintptr(height), 0, 0, instance, 0)
		if hwnd == 0 {
			ready <- opened{err: "STATUS_WINDOW_CREATE_FAILED"}
			return
		}
		w.hwnd = hwnd
		taskbarMessage, _ := windows.UTF16PtrFromString("TaskbarCreated")
		m, _, _ := appUser.NewProc("RegisterWindowMessageW").Call(uintptr(unsafe.Pointer(taskbarMessage)))
		w.taskbarCreated = uint32(m)
		appWindows.Lock()
		appWindows.byHandle[hwnd] = w
		appWindows.Unlock()
		// At program end the icon goes first, not after the renderer join below.
		if currentServiceUIProxy() != nil { // standalone keeps the restoring tooltip until closeUI
			removeTrayOnCancel(ctx, func() { appUser.NewProc("PostMessageW").Call(hwnd, 0x8004, 0, 0) })
		}
		defer func() {
			w.removeTray()
			appUser.NewProc("DestroyWindow").Call(hwnd)
			for _, f := range []uintptr{w.font, w.headingFont, w.valueFont} {
				if f != 0 {
					appGDI.NewProc("DeleteObject").Call(f)
				}
			}
			appWindows.Lock()
			delete(appWindows.byHandle, hwnd)
			appWindows.Unlock()
		}()
		fontName, _ := windows.UTF16PtrFromString("Segoe UI")
		// Negative logical font height, expressed as the signed Win32 LONG.
		w.font, _, _ = appGDI.NewProc("CreateFontW").Call(uintptr(uint32(int32(-w.dip(16)))), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(fontName)))
		if w.font == 0 {
			w.font, _, _ = appGDI.NewProc("GetStockObject").Call(17)
		}
		w.headingFont, _, _ = appGDI.NewProc("CreateFontW").Call(uintptr(uint32(int32(-w.dip(24)))), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(fontName)))
		w.valueFont, _, _ = appGDI.NewProc("CreateFontW").Call(uintptr(uint32(int32(-w.dip(22)))), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(fontName)))
		corner := uint32(2)
		if fn := windows.NewLazySystemDLL("dwmapi.dll").NewProc("DwmSetWindowAttribute"); fn.Find() == nil {
			fn.Call(hwnd, 33, uintptr(unsafe.Pointer(&corner)), 4)
		}
		child := func(kind, text string, style, id uintptr) uintptr {
			k, _ := windows.UTF16PtrFromString(kind)
			t, _ := windows.UTF16PtrFromString(text)
			h, _, _ := appUser.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(k)), uintptr(unsafe.Pointer(t)), 0x50000000|style, 0, 0, 1, 1, hwnd, id, instance, 0)
			if h != 0 {
				appUser.NewProc("SendMessageW").Call(h, 0x30, w.font, 1)
			}
			return h
		}
		w.title = child("STATIC", "正在準備 USB 連線…", 0, 0)
		w.ip = child("EDIT", "正在準備地址", 0x800|0x80|0x10000, 0)
		w.copy = child("BUTTON", "複製電腦 IP", 0x10000, 100)
		w.details = child("EDIT", "", 0x00800000|0x00200000|0x4|0x40|0x800|0x10000, 0)
		w.tx = child("STATIC", "", 0, 0)
		w.rx = child("STATIC", "", 0, 0)
		for _, h := range []uintptr{w.title, w.ip} {
			appUser.NewProc("SendMessageW").Call(h, 0x30, w.headingFont, 1)
		}
		for _, h := range []uintptr{w.tx, w.rx} {
			appUser.NewProc("SendMessageW").Call(h, 0x30, w.valueFont, 1)
		}
		w.settings = child("BUTTON", "設定", 0x10000, 103)
		w.notice = child("STATIC", "關閉視窗會留在背景；用「結束」退出並恢復設定。", 0, 0)
		w.stream = child("BUTTON", "串流體驗正常", 0x10000, 102)
		w.retry = child("BUTTON", "重試連線", 0x10000, 105)
		w.stop = child("BUTTON", "結束程式", 0x10000, 101)
		if currentServiceUIProxy() != nil {
			appSetText(w.notice, "關閉視窗會縮至托盤；「退出程序」先停止連線並核對恢復。")
			appSetText(w.stop, "退出程序")
		}
		if w.retry == 0 || w.settings == 0 || w.tx == 0 || w.rx == 0 || w.title == 0 || w.ip == 0 || w.copy == 0 || w.details == 0 || w.notice == 0 || w.stream == 0 || w.stop == 0 {
			ready <- opened{err: "STATUS_WINDOW_CONTROLS_FAILED"}
			return
		}
		w.layout()
		w.refresh()
		timer, _, _ := appUser.NewProc("SetTimer").Call(hwnd, 1, 1000, 0)
		if timer == 0 {
			ready <- opened{err: "STATUS_WINDOW_TIMER_FAILED"}
			return
		}
		w.addTray()
		show := uintptr(1)
		if desktopLauncher != nil {
			uiCtx, endUI := context.WithCancel(context.Background())
			appWindows.Lock()
			w.modern = &modernUI{ctx: ctx, lifetime: uiCtx, endUI: endUI, state: s, cancel: cancel, refresh: make(chan struct{}, 1)}
			appWindows.Unlock()
			defer func() { w.removeTray(); w.modern.close() }()
			go w.modern.run()
			if s.Minimized || w.modern.show("connection-window-start") || ctx.Err() != nil {
				show = 0
			}
		}
		if s.Minimized {
			if w.modern != nil {
				show = 0
			} else {
				show = 2
			}
		}
		if ctx.Err() != nil {
			show = 0
		}
		appUser.NewProc("ShowWindow").Call(hwnd, show)
		appUser.NewProc("UpdateWindow").Call(hwnd)
		ready <- opened{hwnd: hwnd}
		var msg appWindowMessage
		for {
			v, _, _ := appUser.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if int32(v) == -1 {
				s.update(func(r *ApplicationResult) { r.Error = "STATUS_WINDOW_MESSAGE_FAILED" })
				cancel()
				return
			}
			if v == 0 {
				return
			}
			// Normal tab navigation through native controls.
			handled, _, _ := appUser.NewProc("IsDialogMessageW").Call(hwnd, uintptr(unsafe.Pointer(&msg)))
			if handled == 0 {
				appUser.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg)))
				appUser.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg)))
			}
		}
	}()
	r := <-ready
	if r.err != "" {
		<-done
		return nil, r.err
	}
	var once sync.Once
	return func() { once.Do(func() { appUser.NewProc("PostMessageW").Call(r.hwnd, 0x8001, 0, 0); <-done }) }, ""
}

// SDK NOTIFYICONDATAW (amd64). System-provided icon; no external image files.
type appTrayData struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Timeout             uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                windows.GUID
	BalloonIcon         uintptr
}

// A duplicate verified login asks this process to show its own existing UI.
// Post to the UI thread rather than creating controls from the IPC reader.
func ShowExistingConnectionUI() {
	appWindows.Lock()
	defer appWindows.Unlock()
	for hwnd := range appWindows.byHandle {
		appUser.NewProc("PostMessageW").Call(hwnd, 0x111, 104, 0)
	}
}

func (w *appWindow) addTray() {
	if w.trayRemoved {
		return
	}
	n := appTrayData{Window: w.hwnd, ID: 1, Flags: 7, Callback: 0x8002}
	if unsafe.Sizeof(n) != 976 {
		return
	}
	n.Size = uint32(unsafe.Sizeof(n))
	// Group icon 1 is embedded in the launcher by windows_resource.py.
	// LR_SHARED keeps ownership with the module across Explorer restarts.
	instance, _, _ := appKernel.NewProc("GetModuleHandleW").Call(0)
	width, _, _ := appUser.NewProc("GetSystemMetrics").Call(49)  // SM_CXSMICON
	height, _, _ := appUser.NewProc("GetSystemMetrics").Call(50) // SM_CYSMICON
	n.Icon, _, _ = appUser.NewProc("LoadImageW").Call(instance, 1, 1, width, height, 0x8000)
	if n.Icon == 0 {
		return
	}
	w.trayTip = trayTip
	if currentExitTip.Load() {
		w.trayTip = trayExitTip
	}
	tip, _ := windows.UTF16FromString(w.trayTip)
	copy(n.Tip[:], tip)
	ok, _, _ := windows.NewLazySystemDLL("shell32.dll").NewProc("Shell_NotifyIconW").Call(0, uintptr(unsafe.Pointer(&n)))
	w.tray = ok != 0
}

// While the program exits the window is hidden; the tray tooltip is the only
// visible state.
const (
	trayTip     = "USB Link · 連線管理"
	trayExitTip = "USB Link · 正在結束並還原設定…"
)

var currentExitTip atomic.Bool

func setTrayExitState(exiting bool) {
	currentExitTip.Store(exiting)
	// Tray calls stay on each window's own thread.
	appWindows.Lock()
	defer appWindows.Unlock()
	for hwnd := range appWindows.byHandle {
		appUser.NewProc("PostMessageW").Call(hwnd, 0x8003, 0, 0)
	}
}
func (w *appWindow) setTrayTip(tip string) {
	if !w.tray || w.trayTip == tip {
		return
	}
	n := appTrayData{Window: w.hwnd, ID: 1, Flags: 4}
	n.Size = uint32(unsafe.Sizeof(n))
	text, _ := windows.UTF16FromString(tip)
	copy(n.Tip[:], text)
	if ok, _, _ := windows.NewLazySystemDLL("shell32.dll").NewProc("Shell_NotifyIconW").Call(1, uintptr(unsafe.Pointer(&n))); ok != 0 {
		w.trayTip = tip
	}
}
func (w *appWindow) removeTray() {
	w.trayRemoved = true
	defer w.trayAck.release()
	if !w.tray {
		return
	}
	n := appTrayData{Size: uint32(unsafe.Sizeof(appTrayData{})), Window: w.hwnd, ID: 1}
	windows.NewLazySystemDLL("shell32.dll").NewProc("Shell_NotifyIconW").Call(2, uintptr(unsafe.Pointer(&n)))
	w.tray = false
}
func (w *appWindow) trayMenu() {
	h, _, _ := appUser.NewProc("CreatePopupMenu").Call()
	if h == 0 {
		return
	}
	defer appUser.NewProc("DestroyMenu").Call(h)
	for _, v := range []struct {
		id    uintptr
		label string
	}{{104, "顯示連線狀態"}, {103, "設定"}, {105, "重試連線"}, {101, "結束程式"}} {
		if v.id == 101 && currentServiceUIProxy() != nil {
			v.label = "退出程序"
		}
		p, _ := windows.UTF16PtrFromString(v.label)
		flags := uintptr(0)
		if v.id == 105 && w.state.snapshot().Status != "MONITOR_PAUSED" {
			flags = 1
		}
		appUser.NewProc("AppendMenuW").Call(h, flags, v.id, uintptr(unsafe.Pointer(p)))
	}
	var point struct{ X, Y int32 }
	appUser.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&point)))
	appUser.NewProc("SetForegroundWindow").Call(w.hwnd)
	appUser.NewProc("TrackPopupMenu").Call(h, 0x2, uintptr(point.X), uintptr(point.Y), 0, w.hwnd, 0)
	appUser.NewProc("PostMessageW").Call(w.hwnd, 0, 0, 0)
}

var _ [976 - int(unsafe.Sizeof(appTrayData{}))]byte
var _ [int(unsafe.Sizeof(appTrayData{})) - 976]byte

// RemoveTrayAndWait deletes every status-window tray icon on its own thread and
// waits briefly for the acknowledgement. Call it before the process ends.
func RemoveTrayAndWait() bool {
	appWindows.Lock()
	var hwnds []uintptr
	var acks []*trayRemovalAck
	for h, w := range appWindows.byHandle {
		hwnds = append(hwnds, h)
		acks = append(acks, w.trayAck)
	}
	appWindows.Unlock()
	return removeTraysAndWait(acks, func(i int) { appUser.NewProc("PostMessageW").Call(hwnds[i], 0x8004, 0, 0) }, trayRemovalTimeout)
}

// ExitAfterTrayRemoval deletes the icons, then runs terminate.
func ExitAfterTrayRemoval(terminate func()) { terminateAfterTrayRemoval(RemoveTrayAndWait, terminate) }
