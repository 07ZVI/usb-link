//go:build windows && amd64

package setupwizard

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"
)

type Config struct {
	Version, Directory, License string
	Work                        func(context.Context, Options, func(string)) (string, error)
	Inspect                     func() (string, []byte)
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

type controlLayout struct {
	handle              uintptr
	x, y, width, height int
	fontRole            int
}

type wizard struct {
	layouts                                                                  []controlLayout
	config                                                                   Config
	model                                                                    Model
	ctx                                                                      context.Context
	cancel                                                                   context.CancelFunc
	hwnd, instance                                                           uintptr
	dpi                                                                      int
	font, headingFont, smallFont, brandFont                                  uintptr
	whiteBrush, sidebarBrush, borderBrush                                    uintptr
	highContrast                                                             bool
	brand, brandNote, versionLabel, subtitle, intro, footer, inspect, export uintptr
	steps                                                                    [5]uintptr
	descriptions                                                             [4]uintptr
	inspected                                                                chan inspectionResult
	inspecting                                                               bool
	report                                                                   []byte
	inspectionText                                                           string
	heading, body, agree, core, network, ipad, mac, launch, bar              uintptr
	back, next, stop                                                         uintptr
	closed, running, cancelling, succeeded                                   bool
	open                                                                     bool
	installed                                                                string
	done                                                                     chan outcome
	progressMu                                                               sync.Mutex
	progress                                                                 string
}

type inspectionResult struct {
	text   string
	report []byte
}

var user = windows.NewLazySystemDLL("user32.dll")
var kernel = windows.NewLazySystemDLL("kernel32.dll")
var gdi = windows.NewLazySystemDLL("gdi32.dll")
var exclusive sync.Mutex
var active *wizard // Only the window's locked UI thread reads or writes this.
var callback = windows.NewCallback(windowProc)

const (
	idBack    = 101
	idNext    = 102
	idCancel  = 2
	idAgree   = 103
	idIPad    = 104
	idMac     = 105
	idLaunch  = 106
	idInspect = 107
	idExport  = 108
)

func windowProc(hwnd uintptr, msg uint32, w, l uintptr) uintptr {
	p := active
	if p != nil && p.hwnd == hwnd {
		switch msg {
		case 0x2e0: // WM_DPICHANGED
			p.changeDPI(w, l)
			return 0
		case 0x1a: // System colors/high contrast can change while the wizard is open.
			p.initColors()
			user.NewProc("RedrawWindow").Call(p.hwnd, 0, 0, 0x185)
			return 0
		case 0xf: // WM_PAINT
			p.paint()
			return 0
		case 0x138, 0x133, 0x135: // Static and read-only edit controls.
			return p.controlColor(w, l)
		case 0x10: // WM_CLOSE
			p.close()
			return 0
		case 0x111: // WM_COMMAND
			if w>>16 != 0 {
				break
			} // Button clicks only.
			switch int(w & 0xffff) {
			case idInspect:
				p.startInspection()
			case idExport:
				p.exportReport()
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
	p := &wizard{config: config, ctx: ctx, cancel: cancel, dpi: 96, done: make(chan outcome, 1), inspected: make(chan inspectionResult, 1)}
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
	p.dpi = min(p.dpi, max(48, int(sw-32)*96/900), max(48, int(sh-64)*96/660))
	bounds := rect{Right: int32(p.scale(860)), Bottom: int32(p.scale(600))}
	user.NewProc("AdjustWindowRectEx").Call(uintptr(unsafe.Pointer(&bounds)), 0xc80000, 0, 0x10000)
	width, height := uintptr(bounds.Right-bounds.Left), uintptr(bounds.Bottom-bounds.Top)
	p.hwnd, _, err = user.NewProc("CreateWindowExW").Call(0x10000, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("USB Link 安装向导"))), 0xc80000|0x2000000, (sw-min(sw, width))/2, (sh-min(sh, height))/2, width, height, 0, 0, p.instance, 0)
	if p.hwnd == 0 {
		return "", false, fmt.Errorf("SETUP_WINDOW: %w", err)
	}
	active = p
	defer func() {
		user.NewProc("KillTimer").Call(p.hwnd, 1)
		user.NewProc("DestroyWindow").Call(p.hwnd)
		active = nil
		for _, h := range []uintptr{p.font, p.headingFont, p.smallFont, p.brandFont, p.whiteBrush, p.sidebarBrush, p.borderBrush} {
			if h != 0 {
				gdi.NewProc("DeleteObject").Call(h)
			}
		}
	}()
	p.font = p.makeFont(16, 400)
	p.headingFont = p.makeFont(26, 600)
	p.smallFont = p.makeFont(14, 400)
	p.brandFont = p.makeFont(28, 600)
	p.initColors()
	if !p.createControls() {
		return "", false, errors.New("SETUP_CONTROLS_UNAVAILABLE")
	}
	if timer, _, _ := user.NewProc("SetTimer").Call(p.hwnd, 1, 100, 0); timer == 0 {
		return "", false, errors.New("SETUP_TIMER_UNAVAILABLE")
	}
	p.render()
	p.startInspection()
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
		role := 0
		if font == p.headingFont {
			role = 1
		}
		if font == p.smallFont {
			role = 2
		}
		if font == p.brandFont {
			role = 3
		}
		p.layouts = append(p.layouts, controlLayout{h, x, y, width, height, role})
	}
	return h
}
func (p *wizard) createControls() bool {
	p.brand = p.control("STATIC", "USB Link", 0, 24, 36, 160, 42, 0, p.brandFont)
	p.brandNote = p.control("STATIC", "让设备通过 USB 连接", 0, 24, 86, 168, 36, 0, p.smallFont)
	p.versionLabel = p.control("STATIC", "版本 "+p.config.Version, 0, 24, 510, 164, 24, 0, p.smallFont)
	for i := range p.steps {
		p.steps[i] = p.control("STATIC", "", 0, 24, 170+i*54, 164, 30, 0, p.font)
	}
	p.heading = p.control("STATIC", "", 0, 236, 34, 592, 42, 0, p.headingFont)
	p.subtitle = p.control("STATIC", "", 0, 236, 85, 592, 44, 0, p.font)
	p.intro = p.control("STATIC", "", 0, 252, 144, 556, 62, 0, p.font)
	// Selectable text uses a native edit control, with an inset panel around it.
	p.body = p.control("EDIT", "", 0x4|0x40|0x800|0x200000|0x10000, 252, 222, 556, 234, 0, p.font)
	user.NewProc("SendMessageW").Call(p.body, 0xc5, 2<<20, 0)
	p.agree = p.control("BUTTON", "我已阅读并同意许可条款", 0x3|0x10000, 236, 490, 592, 30, idAgree, p.font)
	titles := []string{"USB Link 程序与桌面界面", "Wintun 网络驱动", "iPad 通信组件与 USB 驱动包", "Mac USB 驱动准备工具"}
	details := []string{"必需 · 已有兼容 .NET 桌面运行库会直接复用", "必需 · 官方组件已内置安装包", "可选 · 使用本地离线包或官方下载，单独确认 Apple 条款", "可选 · 工具已内置，连接设备时再确认驱动操作"}
	controls := []*uintptr{&p.core, &p.network, &p.ipad, &p.mac}
	for i, h := range controls {
		id := 0
		if i == 2 {
			id = idIPad
		}
		if i == 3 {
			id = idMac
		}
		*h = p.control("BUTTON", titles[i], 0x3|0x10000, 252, 180+i*78, 556, 28, id, p.font)
		p.descriptions[i] = p.control("STATIC", details[i], 0, 274, 212+i*78, 532, 32, 0, p.smallFont)
	}
	p.launch = p.control("BUTTON", "完成后启动 USB Link", 0x3|0x10000, 236, 490, 592, 30, idLaunch, p.font)
	p.check(p.core, true)
	p.check(p.network, true)
	p.check(p.launch, true)
	p.enable(p.core, false)
	p.enable(p.network, false)
	p.inspect = p.control("BUTTON", "重新检查", 0x10000, 236, 490, 120, 32, idInspect, p.font)
	p.export = p.control("BUTTON", "保存检查报告…", 0x10000, 368, 490, 162, 32, idExport, p.font)
	p.footer = p.control("STATIC", "", 0, 236, 559, 264, 24, 0, p.smallFont)
	p.back = p.control("BUTTON", "上一步", 0x10000, 504, 548, 100, 36, idBack, p.font)
	p.next = p.control("BUTTON", "下一步", 0x10000|1, 616, 548, 100, 36, idNext, p.font)
	p.stop = p.control("BUTTON", "取消", 0x10000, 728, 548, 100, 36, idCancel, p.font)
	init := struct{ Size, Classes uint32 }{8, 0x20}
	windows.NewLazySystemDLL("comctl32.dll").NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&init)))
	p.bar = p.control("msctls_progress32", "", 0x8, 252, 460, 556, 16, 0, p.font)
	for _, h := range []uintptr{p.brand, p.brandNote, p.versionLabel, p.heading, p.subtitle, p.intro, p.body, p.agree, p.core, p.network, p.ipad, p.mac, p.launch, p.inspect, p.export, p.footer, p.back, p.next, p.stop} {
		if h == 0 {
			return false
		}
	}
	for _, h := range p.steps {
		if h == 0 {
			return false
		}
	}
	for _, h := range p.descriptions {
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
	for _, h := range []uintptr{p.intro, p.agree, p.core, p.network, p.ipad, p.mac, p.launch, p.bar, p.inspect, p.export} {
		p.show(h, false)
	}
	for _, h := range p.descriptions {
		p.show(h, false)
	}
	p.show(p.body, true)
	p.enable(p.back, p.model.Page > Welcome && p.model.Page < Installing)
	p.enable(p.next, p.model.Page != Installing)
	p.enable(p.stop, p.model.Page != Finished)
	p.set(p.next, "下一步")
	p.set(p.footer, fmt.Sprintf("步骤 %d / 5", min(int(p.model.Page)+1, 5)))
	names := []string{"欢迎与检查", "许可条款", "安装组件", "确认安装", "安装与完成"}
	for i, h := range p.steps {
		mark := fmt.Sprintf("%d", i+1)
		if i < min(int(p.model.Page), 4) {
			mark = "✓"
		}
		p.set(h, mark+"   "+names[i])
	}
	user.NewProc("MoveWindow").Call(p.body, p.scale(252), p.scale(154), p.scale(556), p.scale(316), 1)
	switch p.model.Page {
	case Welcome:
		p.set(p.heading, "欢迎安装 USB Link")
		p.set(p.subtitle, "通过 USB 连接 Mac 与 iPad，管理共享文件和设备。")
		p.set(p.intro, "安装位置："+p.config.Directory+"\r\n已有兼容组件会复用；升级完成后会清理旧程序文件。")
		p.show(p.intro, true)
		user.NewProc("MoveWindow").Call(p.body, p.scale(252), p.scale(222), p.scale(556), p.scale(248), 1)
		text := p.inspectionText
		if text == "" {
			if p.config.Inspect == nil {
				text = "此向导将安装或更新 USB Link。"
			} else {
				text = "正在读取现有安装状态…"
			}
		}
		p.set(p.body, text)
		p.show(p.inspect, p.config.Inspect != nil)
		p.show(p.export, p.config.Inspect != nil)
		p.enable(p.inspect, !p.inspecting)
		p.enable(p.export, len(p.report) > 0 && !p.inspecting)
	case License:
		p.set(p.heading, "许可条款")
		p.set(p.subtitle, "请阅读以下条款。接受后才能继续安装。")
		p.set(p.body, p.config.License)
		p.check(p.agree, p.model.Accepted)
		p.show(p.agree, true)
		p.enable(p.next, p.model.Accepted)
	case Components:
		p.set(p.heading, "选择安装组件")
		p.set(p.subtitle, "必需组件已选定。勾选需要为你的设备准备的可选组件。")
		p.show(p.body, false)
		for _, h := range []uintptr{p.core, p.network, p.ipad, p.mac} {
			p.show(h, true)
		}
		for _, h := range p.descriptions {
			p.show(h, true)
		}
		p.check(p.ipad, p.model.Options.IPad)
		p.check(p.mac, p.model.Options.MacTools)
	case Ready:
		p.set(p.heading, "准备安装")
		p.set(p.subtitle, "确认位置和组件后，点击「安装」开始。")
		p.set(p.body, p.model.Options.Summary(p.config.Version, p.config.Directory))
		p.set(p.next, "安装")
	case Installing:
		p.set(p.heading, "正在安装 USB Link")
		p.set(p.subtitle, "请保持窗口打开。安装状态会显示在下面。")
		p.set(p.body, "正在检查现有安装…")
		user.NewProc("MoveWindow").Call(p.body, p.scale(252), p.scale(174), p.scale(556), p.scale(266), 1)
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
			p.set(p.heading, "USB Link 已安装")
			p.set(p.subtitle, "安装完成，可以开始连接设备。")
			p.set(p.body, "版本："+p.config.Version+"\r\n\r\n安装位置："+p.config.Directory+"\r\n\r\n可选设备驱动会在连接时核验并确认。\r\n可在 Windows「已安装的应用」中卸载 USB Link。")
			p.show(p.launch, true)
		} else {
			p.set(p.subtitle, "请查看详细原因。需要恢复的文件与记录已保留。")
		}
	}
	user.NewProc("InvalidateRect").Call(p.hwnd, 0, 1)
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
	select {
	case result := <-p.inspected:
		p.inspecting = false
		p.report = result.report
		p.inspectionText = result.text
		if p.model.Page == Welcome {
			p.set(p.body, result.text)
			p.enable(p.inspect, true)
			p.enable(p.export, len(p.report) > 0)
		}
	default:
	}

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

func (p *wizard) startInspection() {
	if p.config.Inspect == nil || p.inspecting || p.running {
		return
	}
	p.inspecting = true
	p.report = nil
	p.inspectionText = "正在读取现有安装状态…"
	if p.model.Page == Welcome {
		p.set(p.body, p.inspectionText)
		p.enable(p.inspect, false)
		p.enable(p.export, false)
	}
	go func() { text, report := p.config.Inspect(); p.inspected <- inspectionResult{text, report} }()
}

// These are the amd64 SDK layouts for PAINTSTRUCT, HIGHCONTRASTW and
// OPENFILENAMEW. Native controls keep keyboard and accessibility semantics.
type paintStruct struct {
	DC                 uintptr
	Erase              int32
	Paint              rect
	Restore, IncUpdate int32
	Reserved           [32]byte
}
type highContrast struct {
	Size, Flags uint32
	Scheme      *uint16
}
type openFileName struct {
	Size                         uint32
	Owner, Instance              uintptr
	Filter, CustomFilter         *uint16
	MaxCustomFilter, FilterIndex uint32
	File                         *uint16
	MaxFile                      uint32
	FileTitle                    *uint16
	MaxFileTitle                 uint32
	InitialDir, Title            *uint16
	Flags                        uint32
	FileOffset, FileExtension    uint16
	DefaultExtension             *uint16
	CustomData, Hook             uintptr
	Template                     *uint16
	Reserved                     uintptr
	Reserved2, FlagsEx           uint32
}

func (p *wizard) initColors() {
	for _, h := range []uintptr{p.whiteBrush, p.sidebarBrush, p.borderBrush} {
		if h != 0 {
			gdi.NewProc("DeleteObject").Call(h)
		}
	}
	hc := highContrast{Size: uint32(unsafe.Sizeof(highContrast{}))}
	user.NewProc("SystemParametersInfoW").Call(0x42, uintptr(hc.Size), uintptr(unsafe.Pointer(&hc)), 0)
	p.highContrast = hc.Flags&1 != 0
	color := uintptr(0xffffff)
	side := uintptr(0x3c271a)
	border := uintptr(0xede7e2)
	if p.highContrast {
		color, _, _ = user.NewProc("GetSysColor").Call(5)
		side = color
		border, _, _ = user.NewProc("GetSysColor").Call(15)
	}
	p.whiteBrush, _, _ = gdi.NewProc("CreateSolidBrush").Call(color)
	p.sidebarBrush, _, _ = gdi.NewProc("CreateSolidBrush").Call(side)
	p.borderBrush, _, _ = gdi.NewProc("CreateSolidBrush").Call(border)
}
func (p *wizard) controlColor(dc, h uintptr) uintptr {
	sidebar := h == p.brand || h == p.brandNote || h == p.versionLabel
	current := false
	for i, s := range p.steps {
		if s == h {
			sidebar = true
			current = i == min(int(p.model.Page), 4)
		}
	}
	bg, fg := uintptr(0xffffff), uintptr(0x37291e)
	brush := p.whiteBrush
	if sidebar {
		bg = 0x3c271a
		fg = 0xcebead
		brush = p.sidebarBrush
		if h == p.brand || current {
			fg = 0xffffff
		}
	}
	if h == p.subtitle || h == p.footer {
		fg = 0x74675c
	}
	if p.highContrast {
		bg, _, _ = user.NewProc("GetSysColor").Call(5)
		fg, _, _ = user.NewProc("GetSysColor").Call(8)
	}
	gdi.NewProc("SetBkColor").Call(dc, bg)
	gdi.NewProc("SetTextColor").Call(dc, fg)
	return brush
}
func (p *wizard) paint() {
	var ps paintStruct
	dc, _, _ := user.NewProc("BeginPaint").Call(p.hwnd, uintptr(unsafe.Pointer(&ps)))
	defer user.NewProc("EndPaint").Call(p.hwnd, uintptr(unsafe.Pointer(&ps)))
	fill := func(x, y, w, h int, brush uintptr) {
		r := rect{int32(p.scale(x)), int32(p.scale(y)), int32(p.scale(x + w)), int32(p.scale(y + h))}
		user.NewProc("FillRect").Call(dc, uintptr(unsafe.Pointer(&r)), brush)
	}
	fill(0, 0, 860, 600, p.whiteBrush)
	fill(0, 0, 204, 600, p.sidebarBrush)
	fill(204, 532, 656, 1, p.borderBrush)
	if p.model.Page == Components {
		for i := 0; i < 4; i++ {
			fill(236, 166+i*78, 592, 72, p.borderBrush)
			fill(237, 167+i*78, 590, 70, p.whiteBrush)
		}
	} else {
		fill(236, 136, 592, 348, p.borderBrush)
		fill(237, 137, 590, 346, p.whiteBrush)
	}
	// A small accent rail marks the active step without replacing native text.
	brush, _, _ := gdi.NewProc("CreateSolidBrush").Call(0xd8b364)
	if p.highContrast {
		gdi.NewProc("DeleteObject").Call(brush)
		brush, _, _ = user.NewProc("GetSysColorBrush").Call(13)
	} else {
		defer gdi.NewProc("DeleteObject").Call(brush)
	}
	fill(8, 170+min(int(p.model.Page), 4)*54, 3, 28, brush)
}
func (p *wizard) exportReport() {
	if len(p.report) == 0 || p.running {
		return
	}
	filename := make([]uint16, 32768)
	copy(filename, windows.StringToUTF16("USB-Link-install-state.json"))
	filter := utf16.Encode([]rune("JSON 检查报告\x00*.json\x00\x00"))
	ofn := openFileName{Size: uint32(unsafe.Sizeof(openFileName{})), Owner: p.hwnd, Filter: &filter[0], FilterIndex: 1, File: &filename[0], MaxFile: uint32(len(filename)), Title: windows.StringToUTF16Ptr("保存安装检查报告"), DefaultExtension: windows.StringToUTF16Ptr("json"), Flags: 0x800 | 0x2 | 0x8 | 0x80000 | 0x10000000}
	ok, _, _ := windows.NewLazySystemDLL("comdlg32.dll").NewProc("GetSaveFileNameW").Call(uintptr(unsafe.Pointer(&ofn)))
	if ok == 0 {
		return
	}
	if err := os.WriteFile(windows.UTF16ToString(filename), p.report, 0600); err != nil {
		user.NewProc("MessageBoxW").Call(p.hwnd, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("报告保存失败："+err.Error()))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("USB Link"))), 0x10)
		return
	}
	p.set(p.footer, "检查报告已保存")
}

// Fail cross-compilation if SDK structure layouts drift.
var _ [152 - unsafe.Sizeof(openFileName{})]byte
var _ [unsafe.Sizeof(openFileName{}) - 152]byte
var _ [72 - unsafe.Sizeof(paintStruct{})]byte
var _ [unsafe.Sizeof(paintStruct{}) - 72]byte

func (p *wizard) changeDPI(w, l uintptr) {
	dpi := int(w & 0xffff)
	if dpi < 48 || dpi > 768 || l == 0 {
		return
	}
	p.dpi = dpi
	old := []uintptr{p.font, p.headingFont, p.smallFont, p.brandFont}
	p.font = p.makeFont(16, 400)
	p.headingFont = p.makeFont(26, 600)
	p.smallFont = p.makeFont(14, 400)
	p.brandFont = p.makeFont(28, 600)
	fonts := []uintptr{p.font, p.headingFont, p.smallFont, p.brandFont}
	for _, c := range p.layouts {
		user.NewProc("MoveWindow").Call(c.handle, p.scale(c.x), p.scale(c.y), p.scale(c.width), p.scale(c.height), 0)
		user.NewProc("SendMessageW").Call(c.handle, 0x30, fonts[c.fontRole], 0)
	}
	for _, h := range old {
		if h != 0 {
			gdi.NewProc("DeleteObject").Call(h)
		}
	}
	var bounds rect
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), l, (*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds), nil); err != nil {
		return
	}
	user.NewProc("SetWindowPos").Call(p.hwnd, 0, uintptr(bounds.Left), uintptr(bounds.Top), uintptr(bounds.Right-bounds.Left), uintptr(bounds.Bottom-bounds.Top), 0x14)
	p.render()
	if p.cancelling {
		p.set(p.body, "正在取消并等待安装安全结束…")
	}
	user.NewProc("RedrawWindow").Call(p.hwnd, 0, 0, 0x185)
}
