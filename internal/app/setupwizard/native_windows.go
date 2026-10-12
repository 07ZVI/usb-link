//go:build windows && amd64

package setupwizard

import (
	"context"
	"encoding/json"
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
	layouts                                                     []controlLayout
	config                                                      Config
	model                                                       Model
	ctx                                                         context.Context
	cancel                                                      context.CancelFunc
	hwnd, instance                                              uintptr
	dpi                                                         int
	font, headingFont                                           uintptr
	subtitle, intro, footer, inspect, export, componentsGroup   uintptr
	descriptions                                                [4]uintptr
	inspected                                                   chan inspectionResult
	inspecting                                                  bool
	inspectionRun                                               uint64
	report                                                      []byte
	inspectionText                                              string
	diagnostics                                                 bool
	installError                                                string
	failedCancelled                                             bool
	heading, body, agree, core, network, ipad, mac, launch, bar uintptr
	back, next, stop                                            uintptr
	closed, running, cancelling, succeeded                      bool
	open                                                        bool
	installed                                                   string
	done                                                        chan outcome
	progressMu                                                  sync.Mutex
	progress                                                    string
}

type inspectionResult struct {
	run    uint64
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
		case 0x1a, 0x15, 0x31a: // Settings, system colors, theme changes.
			// Windows paints every control and background using its defaults.
			user.NewProc("RedrawWindow").Call(p.hwnd, 0, 0, 0x185)
			break
		case 0x10: // WM_CLOSE
			p.close()
			return 0
		case 0x111: // WM_COMMAND
			if w>>16 != 0 {
				break
			} // Button clicks only.
			switch int(w & 0xffff) {
			case idInspect:
				if p.running {
					break
				}
				if !p.diagnostics {
					p.diagnostics = true
					p.render()
				}
				p.startInspection()
			case idExport:
				p.exportReport()
			case idCancel:
				p.close()
			case idBack:
				if p.diagnostics {
					p.diagnostics = false
					p.render()
					break
				}
				p.capture()
				if p.model.Back() {
					p.render()
				}
			case 1, idNext:
				if p.diagnostics {
					p.diagnostics = false
					p.render()
					break
				}
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
	wc := windowClass{Size: uint32(unsafe.Sizeof(windowClass{})), Procedure: callback, Instance: p.instance, Cursor: cursor, Background: 16, Class: class}
	atom, _, err := user.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return "", false, fmt.Errorf("SETUP_WINDOW_CLASS: %w", err)
	}
	defer user.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(class)), p.instance)
	// A captioned, non-resizable wizard; account for the actual non-client area.
	sw, _, _ := user.NewProc("GetSystemMetrics").Call(0)
	sh, _, _ := user.NewProc("GetSystemMetrics").Call(1)
	p.dpi = min(p.dpi, max(48, int(sw-32)*96/680), max(48, int(sh-64)*96/580))
	bounds := rect{Right: int32(p.scale(640)), Bottom: int32(p.scale(520))}
	user.NewProc("AdjustWindowRectEx").Call(uintptr(unsafe.Pointer(&bounds)), 0xc80000, 0, 0x10001)
	width, height := uintptr(bounds.Right-bounds.Left), uintptr(bounds.Bottom-bounds.Top)
	p.hwnd, _, err = user.NewProc("CreateWindowExW").Call(0x10001, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("USB Link 安装向导"))), 0xc80000|0x2000000, (sw-min(sw, width))/2, (sh-min(sh, height))/2, width, height, 0, 0, p.instance, 0)
	if p.hwnd == 0 {
		return "", false, fmt.Errorf("SETUP_WINDOW: %w", err)
	}
	active = p
	defer func() {
		user.NewProc("KillTimer").Call(p.hwnd, 1)
		user.NewProc("DestroyWindow").Call(p.hwnd)
		active = nil
		for _, h := range []uintptr{p.font, p.headingFont} {
			if h != 0 {
				gdi.NewProc("DeleteObject").Call(h)
			}
		}
	}()
	p.font = p.makeFont(false)
	p.headingFont = p.makeFont(true)
	if p.font == 0 || p.headingFont == 0 {
		return "", false, errors.New("SETUP_SYSTEM_FONT_UNAVAILABLE")
	}
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

// LOGFONTW and NONCLIENTMETRICSW have the SDK's fixed Unicode layouts.
// Obtain the user's dialog/message font at this monitor's DPI; no custom face,
// text colors, background painting or owner-drawn controls are used.
type logFont struct {
	Height, Width, Escapement, Orientation, Weight                                              int32
	Italic, Underline, StrikeOut, CharSet, OutPrecision, ClipPrecision, Quality, PitchAndFamily byte
	FaceName                                                                                    [32]uint16
}
type nonClientMetrics struct {
	Size                                                                uint32
	BorderWidth, ScrollWidth, ScrollHeight, CaptionWidth, CaptionHeight int32
	CaptionFont                                                         logFont
	SmallCaptionWidth, SmallCaptionHeight                               int32
	SmallCaptionFont                                                    logFont
	MenuWidth, MenuHeight                                               int32
	MenuFont, StatusFont, MessageFont                                   logFont
	PaddedBorderWidth                                                   int32
}

func (p *wizard) makeFont(bold bool) uintptr {
	metrics := nonClientMetrics{Size: uint32(unsafe.Sizeof(nonClientMetrics{}))}
	var ok uintptr
	if f := user.NewProc("SystemParametersInfoForDpi"); f.Find() == nil {
		ok, _, _ = f.Call(0x29, uintptr(metrics.Size), uintptr(unsafe.Pointer(&metrics)), 0, uintptr(p.dpi))
	}
	if ok == 0 {
		ok, _, _ = user.NewProc("SystemParametersInfoW").Call(0x29, uintptr(metrics.Size), uintptr(unsafe.Pointer(&metrics)), 0)
		if ok == 0 {
			return 0
		}
		dpi := uintptr(96)
		if f := user.NewProc("GetDpiForSystem"); f.Find() == nil {
			dpi, _, _ = f.Call()
		}
		if dpi > 0 {
			metrics.MessageFont.Height = metrics.MessageFont.Height * int32(p.dpi) / int32(dpi)
		}
	}
	font := metrics.MessageFont
	if bold {
		font.Weight = 700
	}
	h, _, _ := gdi.NewProc("CreateFontIndirectW").Call(uintptr(unsafe.Pointer(&font)))
	return h
}
func (p *wizard) control(kind, text string, style uintptr, x, y, width, height, id int, font uintptr) uintptr {
	h, _, _ := user.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(kind))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))), 0x50000000|style, p.scale(x), p.scale(y), p.scale(width), p.scale(height), p.hwnd, uintptr(id), p.instance, 0)
	if h != 0 {
		user.NewProc("SendMessageW").Call(h, 0x30, font, 1)
		role := 0
		if font == p.headingFont {
			role = 1
		}
		p.layouts = append(p.layouts, controlLayout{h, x, y, width, height, role})
	}
	return h
}
func (p *wizard) createControls() bool {
	p.heading = p.control("STATIC", "", 0, 24, 20, 592, 28, 0, p.headingFont)
	p.subtitle = p.control("STATIC", "", 0, 24, 56, 592, 40, 0, p.font)
	p.control("STATIC", "", 0x10, 0, 102, 640, 2, 0, p.font) // Native etched separators.
	p.intro = p.control("STATIC", "", 0, 24, 142, 592, 200, 0, p.font)
	p.body = p.control("EDIT", "", 0x4|0x40|0x800|0x200000|0x10000|0x800000, 24, 118, 592, 290, 0, p.font)
	user.NewProc("SendMessageW").Call(p.body, 0xc5, 2<<20, 0)
	p.agree = p.control("BUTTON", "我已阅读并同意许可条款(&A)", 0x3|0x10000, 24, 416, 592, 28, idAgree, p.font)
	p.componentsGroup = p.control("BUTTON", "安装组件", 0x7, 24, 114, 592, 294, 0, p.font)
	titles := []string{"USB Link 程序与桌面界面", "Wintun 网络驱动", "iPad 通信组件与 USB 驱动包(&P)", "Mac USB 驱动准备工具(&M)"}
	details := []string{"必需；已有兼容运行库会直接复用", "必需；官方组件已内置", "可选；使用离线包或官方下载，单独确认 Apple 条款", "可选；工具已内置，连接设备时确认驱动操作"}
	controls := []*uintptr{&p.core, &p.network, &p.ipad, &p.mac}
	for i, h := range controls {
		id := 0
		if i == 2 {
			id = idIPad
		}
		if i == 3 {
			id = idMac
		}
		*h = p.control("BUTTON", titles[i], 0x3|0x10000, 40, 140+i*64, 556, 24, id, p.font)
		p.descriptions[i] = p.control("STATIC", details[i], 0, 62, 166+i*64, 534, 26, 0, p.font)
	}
	p.launch = p.control("BUTTON", "完成后启动 USB Link(&L)", 0x3|0x10000, 24, 416, 592, 28, idLaunch, p.font)
	p.check(p.core, true)
	p.check(p.network, true)
	p.check(p.launch, true)
	p.enable(p.core, false)
	p.enable(p.network, false)
	p.inspect = p.control("BUTTON", "安装诊断…(&D)", 0x10000, 24, 416, 132, 30, idInspect, p.font)
	p.export = p.control("BUTTON", "保存检查报告…(&S)", 0x10000, 168, 416, 156, 30, idExport, p.font)
	p.control("STATIC", "", 0x10, 0, 462, 640, 2, 0, p.font)
	p.footer = p.control("STATIC", "", 0, 24, 482, 252, 20, 0, p.font)
	p.back = p.control("BUTTON", "< 上一步(&B)", 0x10000, 304, 478, 96, 30, idBack, p.font)
	p.next = p.control("BUTTON", "下一步(&N) >", 0x10000|1, 412, 478, 96, 30, idNext, p.font)
	p.stop = p.control("BUTTON", "取消(&C)", 0x10000, 520, 478, 96, 30, idCancel, p.font)
	init := struct{ Size, Classes uint32 }{8, 0x20}
	windows.NewLazySystemDLL("comctl32.dll").NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&init)))
	p.bar = p.control("msctls_progress32", "", 0x8, 24, 385, 592, 18, 0, p.font)
	for _, h := range []uintptr{p.heading, p.subtitle, p.intro, p.body, p.agree, p.componentsGroup, p.core, p.network, p.ipad, p.mac, p.launch, p.inspect, p.export, p.footer, p.back, p.next, p.stop} {
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
	for _, h := range []uintptr{p.intro, p.agree, p.componentsGroup, p.core, p.network, p.ipad, p.mac, p.launch, p.bar, p.inspect, p.export} {
		p.show(h, false)
	}
	for _, h := range p.descriptions {
		p.show(h, false)
	}
	p.show(p.body, true)
	p.enable(p.back, p.model.Page > Welcome && p.model.Page < Installing)
	p.enable(p.next, p.model.Page != Installing)
	p.enable(p.stop, p.model.Page != Finished)
	p.show(p.next, true)
	p.set(p.back, "< 上一步(&B)")
	p.set(p.inspect, "安装诊断…(&D)")
	p.enable(p.inspect, !p.running)
	p.set(p.next, "下一步(&N) >")
	p.set(p.footer, "版本 "+p.config.Version)
	user.NewProc("MoveWindow").Call(p.body, p.scale(24), p.scale(118), p.scale(592), p.scale(290), 1)
	switch p.model.Page {
	case Welcome:
		p.set(p.heading, "欢迎安装 USB Link")
		p.set(p.subtitle, "让 Mac 和 iPad 通过 USB 连接 Windows。")
		p.set(p.intro, "这个向导将帮助你安装或更新 USB Link。\r\n\r\n点击「下一步」开始。")
		user.NewProc("MoveWindow").Call(p.intro, p.scale(24), p.scale(142), p.scale(592), p.scale(200), 1)
		p.show(p.intro, true)
		p.show(p.body, false)
		p.show(p.inspect, p.config.Inspect != nil)
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
		p.show(p.componentsGroup, true)
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
		p.set(p.body, p.model.Options.Summary(p.config.Version, p.config.Directory)+"\r\n\r\n已删除程序的旧安装记录会在核验并备份后清理。")
		p.set(p.next, "安装(&I)")
	case Installing:
		p.set(p.heading, "正在安装 USB Link")
		p.set(p.subtitle, "请保持窗口打开。安装状态会显示在下面。")
		p.set(p.body, "正在检查现有安装…")
		user.NewProc("MoveWindow").Call(p.body, p.scale(24), p.scale(118), p.scale(592), p.scale(250), 1)
		p.show(p.bar, true)
		if p.bar != 0 {
			user.NewProc("SendMessageW").Call(p.bar, 0x40a, 1, 40)
		}
	case Finished:
		if p.bar != 0 {
			user.NewProc("SendMessageW").Call(p.bar, 0x40a, 0, 0)
		}
		p.set(p.next, "完成(&F)")
		if p.succeeded {
			p.set(p.heading, "USB Link 已安装")
			p.set(p.subtitle, "安装完成，可以开始连接设备。")
			p.set(p.body, "版本："+p.config.Version+"\r\n\r\n安装位置："+p.config.Directory+"\r\n\r\n可选设备驱动会在连接时核验并确认。\r\n可在 Windows「已安装的应用」中卸载 USB Link。")
			p.show(p.launch, true)
		} else {
			p.set(p.heading, "安装未完成")
			if p.failedCancelled {
				p.set(p.heading, "安装已取消")
			}
			p.set(p.subtitle, "请查看详细原因。需要恢复的文件与记录已保留。")
			p.set(p.body, "安装没有完成，已保留需要恢复的文件与记录。\r\n已有共享运行库和 Apple 组件会保留。\r\n\r\n"+p.installError+"\r\n\r\n处理上述问题后，可以再次运行同一安装包。")
			p.show(p.inspect, p.config.Inspect != nil)
		}
	}
	if p.diagnostics {
		p.set(p.heading, "安装诊断")
		p.set(p.subtitle, "查看安装记录和服务状态，也可以保存报告。")
		p.show(p.intro, false)
		p.show(p.launch, false)
		p.show(p.body, true)
		text := p.inspectionText
		if text == "" {
			text = "点击「重新检查」读取安装状态。"
		}
		p.set(p.body, text)
		p.show(p.inspect, true)
		p.set(p.inspect, "重新检查")
		p.show(p.export, true)
		p.enable(p.inspect, !p.inspecting)
		p.enable(p.export, len(p.report) > 0 && !p.inspecting)
		p.set(p.back, "返回安装(&B)")
		p.enable(p.back, true)
		p.show(p.next, false)
		p.set(p.footer, "只读检查")
	}
	user.NewProc("InvalidateRect").Call(p.hwnd, 0, 1)
	if p.diagnostics {
		user.NewProc("SetFocus").Call(p.back)
	} else if p.model.Page == License && !p.model.Accepted {
		user.NewProc("SetFocus").Call(p.agree)
	} else if p.model.Page != Installing {
		user.NewProc("SetFocus").Call(p.next)
	}
}
func (p *wizard) start() {
	p.inspectionRun++ // Ignore a read that began before this installation.
	p.inspecting = false
	p.installError = ""
	p.report = nil
	p.inspectionText = ""
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
		if result.run == p.inspectionRun {
			p.inspecting = false
			p.report = withInstallationFailure(result.report, p.config.Version, p.installError)
			p.inspectionText = result.text
			if p.installError != "" {
				p.inspectionText += "\r\n\r\n本次安装失败：\r\n" + p.installError
			}
			if p.diagnostics {
				p.set(p.body, p.inspectionText)
				p.enable(p.inspect, true)
				p.enable(p.export, len(p.report) > 0)
			}
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
		p.failedCancelled = errors.Is(result.err, context.Canceled)
		if result.err != nil {
			p.installError = result.err.Error()
		}
		if p.succeeded {
			p.installed = result.path
		}
		p.render()
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
	p.inspectionRun++
	run := p.inspectionRun
	p.report = nil
	p.inspectionText = "正在读取现有安装状态…"
	if p.diagnostics {
		p.set(p.body, p.inspectionText)
		p.enable(p.inspect, false)
		p.enable(p.export, false)
	}
	go func() { text, report := p.config.Inspect(); p.inspected <- inspectionResult{run, text, report} }()
}

// The amd64 SDK layout for the standard Windows save-file dialog.
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
var _ [504 - unsafe.Sizeof(nonClientMetrics{})]byte
var _ [unsafe.Sizeof(nonClientMetrics{}) - 504]byte
var _ [92 - unsafe.Sizeof(logFont{})]byte
var _ [unsafe.Sizeof(logFont{}) - 92]byte

func (p *wizard) changeDPI(w, l uintptr) {
	dpi := int(w & 0xffff)
	if dpi < 48 || dpi > 768 || l == 0 {
		return
	}
	p.capture() // Preserve optional checkboxes when moving between monitors.
	p.dpi = dpi
	old := []uintptr{p.font, p.headingFont}
	p.font = p.makeFont(false)
	p.headingFont = p.makeFont(true)
	fonts := []uintptr{p.font, p.headingFont}
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

// Reports from the native inspector contain only installation metadata. Retain
// the actual installer failure too, so a post-failure report explains the gate.
func withInstallationFailure(report []byte, version, problem string) []byte {
	var fields map[string]any
	if json.Unmarshal(report, &fields) != nil || fields == nil {
		return report
	}
	fields["installerVersion"] = version
	if problem != "" {
		fields["installationError"] = problem
	}
	out, e := json.MarshalIndent(fields, "", "  ")
	if e != nil {
		return report
	}
	return append(out, '\n')
}
