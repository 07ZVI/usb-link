//go:build windows && amd64

package setupwizard

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

type Config struct {
	Version, Directory, License string
	Work                        func(context.Context, Options, func(string)) (string, error)
}

type windowClass struct {
	Size, Style                        uint32
	Procedure                          uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Class                        *uint16
	SmallIcon                          uintptr
}

type message struct {
	Window  uintptr
	ID      uint32
	W, L    uintptr
	Time    uint32
	X, Y    int32
	Private uint32
}

type rect struct{ Left, Top, Right, Bottom int32 }

type outcome struct {
	path string
	err  error
}

type wizard struct {
	config                                                      Config
	model                                                       Model
	ctx                                                         context.Context
	cancel                                                      context.CancelFunc
	hwnd, instance                                              uintptr
	dpi                                                         int
	font, headingFont                                           uintptr
	heading, body, agree, core, network, ipad, mac, launch, bar uintptr
	back, next, stop                                            uintptr
	closed, running, cancelling, succeeded                      bool
	open                                                        bool
	installed                                                   string
	done                                                        chan outcome
	progressMu                                                  sync.Mutex
	progress                                                    string
}

var user = windows.NewLazySystemDLL("user32.dll")
var kernel = windows.NewLazySystemDLL("kernel32.dll")
var gdi = windows.NewLazySystemDLL("gdi32.dll")
var exclusive sync.Mutex
var active *wizard // Only the window's locked UI thread reads or writes this.
var callback = windows.NewCallback(windowProc)

const (
	idBack   = 101
	idNext   = 102
	idCancel = 2
	idAgree  = 103
	idIPad   = 104
	idMac    = 105
	idLaunch = 106
)

func windowProc(hwnd uintptr, msg uint32, w, l uintptr) uintptr {
	p := active
	if p != nil && p.hwnd == hwnd {
		switch msg {
		case 0x10: // WM_CLOSE
			p.close()
			return 0
		case 0x111: // WM_COMMAND
			if w>>16 != 0 {
				break
			} // Button clicks only.
			switch int(w & 0xffff) {
			case idCancel:
				p.close()
			case idBack:
				p.capture()
				if p.model.Back() {
					p.render()
				}
			case 1, idNext:
				p.capture()
				if p.model.Page == Finished {
					p.open = p.succeeded && p.checked(p.launch)
					p.closed = true
				} else if p.model.Next() {
					p.render()
					if p.model.Page == Installing {
						p.start()
					}
				}
			case idAgree:
				p.model.Accepted = p.checked(p.agree)
				p.enable(p.next, p.model.Accepted)
			}
			return 0
		case 0x113: // WM_TIMER
			p.tick()
			return 0
		}
	}
	result, _, _ := user.NewProc("DefWindowProcW").Call(hwnd, uintptr(msg), w, l)
	return result
}

// Run uses normal Windows controls and requires no desktop runtime. Nothing
// invokes Work until the accepted license, component and ready pages complete.
func Run(parent context.Context, config Config) (string, bool, error) {
	if parent.Err() != nil {
		return "", false, nil
	}
	if config.Work == nil || config.License == "" {
		return "", false, errors.New("SETUP_CONTENT_REQUIRED")
	}
	exclusive.Lock()
	defer exclusive.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	p := &wizard{config: config, ctx: ctx, cancel: cancel, dpi: 96, done: make(chan outcome, 1)}
	// DPI awareness is local to this UI thread and restored before returning.
	if f := user.NewProc("SetThreadDpiAwarenessContext"); f.Find() == nil {
		previous, _, _ := f.Call(^uintptr(3)) // PER_MONITOR_AWARE_V2 (-4)
		if previous != 0 {
			defer f.Call(previous)
		}
	}
	p.instance, _, _ = kernel.NewProc("GetModuleHandleW").Call(0)
	if f := user.NewProc("GetDpiForSystem"); f.Find() == nil {
		dpi, _, _ := f.Call()
		if dpi >= 96 && dpi <= 384 {
			p.dpi = int(dpi)
		}
	}
	class := windows.StringToUTF16Ptr("USBLinkSetupWizard")
	cursor, _, _ := user.NewProc("LoadCursorW").Call(0, 32512)
	wc := windowClass{Size: uint32(unsafe.Sizeof(windowClass{})), Procedure: callback, Instance: p.instance, Cursor: cursor, Background: 6, Class: class}
	atom, _, err := user.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return "", false, fmt.Errorf("SETUP_WINDOW_CLASS: %w", err)
	}
	defer user.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(class)), p.instance)
	// A captioned, non-resizable wizard; account for the actual non-client area.
	sw, _, _ := user.NewProc("GetSystemMetrics").Call(0)
	sh, _, _ := user.NewProc("GetSystemMetrics").Call(1)
	p.dpi = min(p.dpi, max(48, int(sw-32)*96/700), max(48, int(sh-64)*96/590))
	bounds := rect{Right: int32(p.scale(660)), Bottom: int32(p.scale(530))}
	user.NewProc("AdjustWindowRectEx").Call(uintptr(unsafe.Pointer(&bounds)), 0xc80000, 0, 0x10000)
	width, height := uintptr(bounds.Right-bounds.Left), uintptr(bounds.Bottom-bounds.Top)
	p.hwnd, _, err = user.NewProc("CreateWindowExW").Call(0x10000, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("USB Link 安装向导"))), 0xc80000, (sw-min(sw, width))/2, (sh-min(sh, height))/2, width, height, 0, 0, p.instance, 0)
	if p.hwnd == 0 {
		return "", false, fmt.Errorf("SETUP_WINDOW: %w", err)
	}
	active = p
	defer func() {
		user.NewProc("KillTimer").Call(p.hwnd, 1)
		user.NewProc("DestroyWindow").Call(p.hwnd)
		active = nil
		if p.font != 0 {
			gdi.NewProc("DeleteObject").Call(p.font)
		}
		if p.headingFont != 0 {
			gdi.NewProc("DeleteObject").Call(p.headingFont)
		}
	}()
	p.font = p.makeFont(16, 400)
	p.headingFont = p.makeFont(24, 600)
	if !p.createControls() {
		return "", false, errors.New("SETUP_CONTROLS_UNAVAILABLE")
	}
	if timer, _, _ := user.NewProc("SetTimer").Call(p.hwnd, 1, 100, 0); timer == 0 {
		return "", false, errors.New("SETUP_TIMER_UNAVAILABLE")
	}
	p.render()
	user.NewProc("ShowWindow").Call(p.hwnd, 1)
	user.NewProc("SetForegroundWindow").Call(p.hwnd)
	var m message
	for !p.closed {
		r, _, err := user.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			// Even an outer message-loop shutdown must drain the transaction.
			p.cancel()
			if p.running {
				<-p.done
			}
			if r == 0 {
				user.NewProc("PostQuitMessage").Call(m.W)
			} else {
				return "", false, fmt.Errorf("SETUP_MESSAGES: %w", err)
			}
			return "", false, nil
		}
		handled, _, _ := user.NewProc("IsDialogMessageW").Call(p.hwnd, uintptr(unsafe.Pointer(&m)))
		if handled == 0 {
			user.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&m)))
			user.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&m)))
		}
	}
	return p.installed, p.open, nil
}

func (p *wizard) scale(n int) uintptr { return uintptr(n * p.dpi / 96) }
func (p *wizard) makeFont(size, weight int) uintptr {
	font, _, _ := gdi.NewProc("CreateFontW").Call(uintptr(uint32(-int32(p.scale(size)))), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Segoe UI"))))
	return font
}
func (p *wizard) control(kind, text string, style uintptr, x, y, width, height, id int, font uintptr) uintptr {
	h, _, _ := user.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(kind))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))), 0x50000000|style, p.scale(x), p.scale(y), p.scale(width), p.scale(height), p.hwnd, uintptr(id), p.instance, 0)
	if h != 0 {
		user.NewProc("SendMessageW").Call(h, 0x30, font, 1)
	}
	return h
}
func (p *wizard) createControls() bool {
	p.heading = p.control("STATIC", "", 0, 28, 24, 604, 44, 0, p.headingFont)
	// Read-only, scrollable, selectable license/status text.
	p.body = p.control("EDIT", "", 0x4|0x40|0x800|0x200000|0x10000, 28, 84, 604, 324, 0, p.font)
	user.NewProc("SendMessageW").Call(p.body, 0xc5, 2<<20, 0) // Explicit bounded license text limit.
	p.agree = p.control("BUTTON", "我已阅读并同意上述许可条款", 0x3|0x10000, 28, 420, 604, 30, idAgree, p.font)
	p.core = p.control("BUTTON", "USB Link 程序与桌面界面（必需；已有运行库则复用）", 0x3|0x10000, 28, 252, 604, 30, 0, p.font)
	p.network = p.control("BUTTON", "Wintun 网络驱动（必需，已内置）", 0x3|0x10000, 28, 292, 604, 30, 0, p.font)
	p.ipad = p.control("BUTTON", "iPad 通信组件与 USB 驱动包（可选）", 0x3|0x10000, 28, 332, 604, 30, idIPad, p.font)
	p.mac = p.control("BUTTON", "Mac USB 驱动准备工具（可选）", 0x3|0x10000, 28, 372, 604, 30, idMac, p.font)
	p.launch = p.control("BUTTON", "完成后启动 USB Link", 0x3|0x10000, 28, 420, 604, 30, idLaunch, p.font)
	p.check(p.core, true)
	p.check(p.network, true)
	p.check(p.launch, true)
	p.enable(p.core, false)
	p.enable(p.network, false)
	p.control("STATIC", "", 0x10, 0, 465, 660, 2, 0, p.font) // System separator.
	p.back = p.control("BUTTON", "上一步", 0x10000, 292, 482, 104, 32, idBack, p.font)
	p.next = p.control("BUTTON", "下一步", 0x10000|1, 406, 482, 104, 32, idNext, p.font)
	p.stop = p.control("BUTTON", "取消", 0x10000, 524, 482, 108, 32, idCancel, p.font)
	// Optional common-control animation. Text and transaction completion remain
	// usable if the progress-bar class is not available on this Windows image.
	init := struct{ Size, Classes uint32 }{8, 0x20}
	windows.NewLazySystemDLL("comctl32.dll").NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&init)))
	p.bar = p.control("msctls_progress32", "", 0x8, 28, 422, 604, 20, 0, p.font)
	for _, h := range []uintptr{p.heading, p.body, p.agree, p.core, p.network, p.ipad, p.mac, p.launch, p.back, p.next, p.stop} {
		if h == 0 {
			return false
		}
	}
	return true
}
func (p *wizard) set(h uintptr, s string) {
	user.NewProc("SetWindowTextW").Call(h, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")))))
}
func (p *wizard) show(h uintptr, visible bool) {
	if h == 0 {
		return
	}
	v := uintptr(0)
	if visible {
		v = 5
	}
	user.NewProc("ShowWindow").Call(h, v)
}
func (p *wizard) enable(h uintptr, enabled bool) {
	v := uintptr(0)
	if enabled {
		v = 1
	}
	user.NewProc("EnableWindow").Call(h, v)
}
func (p *wizard) check(h uintptr, checked bool) {
	v := uintptr(0)
	if checked {
		v = 1
	}
	user.NewProc("SendMessageW").Call(h, 0xf1, v, 0)
}
func (p *wizard) checked(h uintptr) bool {
	v, _, _ := user.NewProc("SendMessageW").Call(h, 0xf0, 0, 0)
	return v == 1
}
func (p *wizard) capture() {
	if p.model.Page == License {
		p.model.Accepted = p.checked(p.agree)
	}
	if p.model.Page == Components {
		p.model.Options = Options{IPad: p.checked(p.ipad), MacTools: p.checked(p.mac)}
	}
}
func (p *wizard) render() {
	for _, h := range []uintptr{p.agree, p.core, p.network, p.ipad, p.mac, p.launch, p.bar} {
		p.show(h, false)
	}
	p.enable(p.back, p.model.Page > Welcome && p.model.Page < Installing)
	p.enable(p.next, p.model.Page != Installing)
	p.enable(p.stop, p.model.Page != Finished)
	p.set(p.next, "下一步")
	user.NewProc("MoveWindow").Call(p.body, p.scale(28), p.scale(84), p.scale(604), p.scale(324), 1)
	switch p.model.Page {
	case Welcome:
		p.set(p.heading, "欢迎安装 USB Link "+p.config.Version)
		p.set(p.body, "此向导将安装或更新 USB Link。\r\n\r\n你可以阅读许可条款、选择需要准备的组件，再确认安装。\r\n\r\n程序安装到：\r\n"+p.config.Directory+"\r\n\r\n设置与恢复记录保存在 Windows 的 ProgramData 中。升级完成后会清理旧程序文件。\r\n\r\n已有兼容组件会直接复用。缺少 .NET 运行库时需要本地准备或联网；Wintun 已随安装包提供。")
	case License:
		p.set(p.heading, "许可条款")
		p.set(p.body, p.config.License)
		p.check(p.agree, p.model.Accepted)
		p.show(p.agree, true)
		p.enable(p.next, p.model.Accepted)
	case Components:
		p.set(p.heading, "选择组件")
		p.set(p.body, "勾选需要在安装期间准备的组件。\r\n\r\n可选组件缺失时，优先读取本地离线包，再从官方来源下载。Apple 安装向导会显示自己的许可条款。\r\n\r\n稍后也可在连接设备时准备可选组件。这里的勾选不会直接更改未确认设备的驱动。")
		user.NewProc("MoveWindow").Call(p.body, p.scale(28), p.scale(84), p.scale(604), p.scale(152), 1)
		for _, h := range []uintptr{p.core, p.network, p.ipad, p.mac} {
			p.show(h, true)
		}
		p.check(p.ipad, p.model.Options.IPad)
		p.check(p.mac, p.model.Options.MacTools)
	case Ready:
		p.set(p.heading, "准备安装")
		p.set(p.body, p.model.Options.Summary(p.config.Version, p.config.Directory))
		p.set(p.next, "安装")
	case Installing:
		p.set(p.heading, "正在安装")
		p.set(p.body, "正在检查现有安装…")
		p.show(p.bar, true)
		if p.bar != 0 {
			user.NewProc("SendMessageW").Call(p.bar, 0x40a, 1, 40)
		}
	case Finished:
		if p.bar != 0 {
			user.NewProc("SendMessageW").Call(p.bar, 0x40a, 0, 0)
		}
		p.set(p.next, "完成")
		if p.succeeded {
			p.set(p.heading, "安装完成")
			p.set(p.body, "USB Link "+p.config.Version+" 已安装。\r\n\r\n安装位置："+p.config.Directory+"\r\n\r\n可选的设备驱动会在连接时核验并确认。你可以在 Windows「已安装的应用」中卸载 USB Link。")
			p.show(p.launch, true)
		} // Failure details are set by tick after rendering the controls.
	}
	if p.model.Page == License && !p.model.Accepted {
		user.NewProc("SetFocus").Call(p.agree)
	} else if p.model.Page != Installing {
		user.NewProc("SetFocus").Call(p.next)
	}
}
func (p *wizard) start() {
	p.running = true
	go func() {
		path, err := p.config.Work(p.ctx, p.model.Options, func(s string) { p.progressMu.Lock(); p.progress = s; p.progressMu.Unlock() })
		p.done <- outcome{path, err}
	}()
}
func (p *wizard) close() {
	if !p.running {
		p.closed = true
		return
	}
	p.cancelling = true
	p.cancel()
	p.enable(p.stop, false)
	p.set(p.body, "正在取消并等待安装安全结束…\r\n\r\n如官方安装向导仍在运行，请在该向导中完成或取消。原版本的恢复与清理结束后才能关闭此窗口。")
}
func (p *wizard) tick() {
	if p.ctx.Err() != nil && !p.cancelling {
		p.close()
	}
	if !p.running {
		return
	}
	select {
	case result := <-p.done:
		p.running = false
		p.model.Page = Finished
		p.succeeded = result.err == nil
		if p.succeeded {
			p.installed = result.path
		}
		p.render()
		if result.err != nil {
			if errors.Is(result.err, context.Canceled) {
				p.set(p.heading, "安装已取消")
			} else {
				p.set(p.heading, "安装未完成")
			}
			p.set(p.body, "安装没有完成，已保留需要恢复的文件与记录。\r\n已有共享运行库和 Apple 组件会保留。\r\n\r\n"+result.err.Error()+"\r\n\r\n处理上述问题后，可以再次运行同一安装包。")
		}
	default:
		if !p.cancelling {
			p.progressMu.Lock()
			text := p.progress
			p.progressMu.Unlock()
			if text != "" {
				p.set(p.body, text)
			}
		}
	}
}
