//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/ipadsession"
	"sync"
)

var connectionSettings = struct {
	sync.Mutex
	dir     string
	p       ipadsession.Preferences
	startup func(bool) error
	ctx     context.Context
	monitor *applicationState
}{p: ipadsession.DefaultPreferences()}

func InitConnectionSettings(dir string, setStartup func(bool) error) error {
	connectionSettings.Lock()
	defer connectionSettings.Unlock()
	connectionSettings.dir = dir
	connectionSettings.startup = setStartup
	path := filepath.Join(dir, "connection-preferences.json")
	p, _ := windows.UTF16PtrFromString(path)
	a, e := windows.GetFileAttributes(p)
	if e == windows.ERROR_FILE_NOT_FOUND {
		connectionSettings.p = ipadsession.DefaultPreferences()
		return nil
	}
	if e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("settings ownership unavailable")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return fmt.Errorf("settings read failed")
	}
	v, e := ipadsession.ParsePreferences(b)
	if e != nil {
		return e
	}
	v.IndependentUSB = true // Automatic USB networking for every detected iPad.
	connectionSettings.p = v
	return nil
}
func SetConnectionContext(ctx context.Context) {
	connectionSettings.Lock()
	connectionSettings.ctx = ctx
	connectionSettings.Unlock()
}
func connectionContext() context.Context {
	connectionSettings.Lock()
	defer connectionSettings.Unlock()
	if connectionSettings.ctx != nil {
		return connectionSettings.ctx
	}
	return context.Background()
}
func connectionMonitor() *applicationState {
	connectionSettings.Lock()
	defer connectionSettings.Unlock()
	return connectionSettings.monitor
}
func StartConnectionMonitor(ctx context.Context, cancel context.CancelFunc, minimized bool) (func(), string) {
	return startConnectionMonitor(ctx, cancel, minimized, true)
}

// The service owns identical state and readiness checks but creates no UI in
// Session 0. Its local authenticated UI client is a separate process.
func StartHeadlessConnectionMonitor(ctx context.Context, cancel context.CancelFunc) (func(), string) {
	return startConnectionMonitor(ctx, cancel, true, false)
}

func startConnectionMonitor(ctx context.Context, cancel context.CancelFunc, minimized, interactive bool) (func(), string) {
	if currentServiceUIProxy() == nil {
		go queryHostSecurity(ctx)
	}
	ipad := &applicationState{r: ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_WAITING", RemainingSeconds: -1, WindowsIPv4: "10.6.9.1", ProposedIPadIPv4: "10.6.9.3"}, Settings: ShowConnectionSettings, Minimized: minimized}
	mac := &applicationState{r: ApplicationResult{DeviceKind: "Mac", Status: "MONITOR_WAITING", RemainingSeconds: -1, WindowsIPv4: "10.6.9.1"}, Settings: ShowConnectionSettings, Minimized: minimized}
	displaySessions.Lock()
	displaySessions.states = map[string]*applicationState{"Mac": mac, "iPad": ipad}
	displaySessions.selected = "Mac"
	displaySessions.manual = false
	displaySessions.Unlock()
	settings := ShowConnectionSettings
	if proxy := currentServiceUIProxy(); proxy != nil {
		settings = func() { go func() { _, _ = proxy.Action(ctx, json.RawMessage(`{"action":"settings"}`)) }() }
	}
	s := &applicationState{Settings: settings, Minimized: minimized, selected: selectedDeviceMonitor}
	closeUI := func() {}
	if interactive {
		var e string
		closeUI, e = startApplicationUI(ctx, s, cancel)
		if e != "" {
			return nil, e
		}
	}
	connectionSettings.Lock()
	connectionSettings.monitor = ipad
	connectionSettings.Unlock()
	return func() {
		connectionSettings.Lock()
		connectionSettings.monitor = nil
		connectionSettings.Unlock()
		closeUI()
		displaySessions.Lock()
		displaySessions.states = nil
		displaySessions.Unlock()
	}, ""
}
func SetMonitorStatus(status, err string) {
	if s := connectionMonitor(); s != nil {
		s.update(func(r *ApplicationResult) {
			r.Status = status
			r.Error = err
			if status == "MONITOR_WAITING" || status == "MONITOR_PAUSED" {
				r.BenchmarkURL = ""
				r.ObservedTransmitMbps = 0
				r.ObservedReceiveMbps = 0
				r.DHCPStarted = false
			}
		})
	}
}
func connectionPreferences() ipadsession.Preferences {
	connectionSettings.Lock()
	defer connectionSettings.Unlock()
	p := connectionSettings.p
	p.Devices = append([]ipadsession.DeviceGrant(nil), p.Devices...)
	p.USBDevices = append([]ipadsession.USBDeviceGrant(nil), p.USBDevices...)
	return p
}
func saveConnectionPreferences(p ipadsession.Preferences) error {
	connectionSettings.Lock()
	defer connectionSettings.Unlock()
	if !p.Valid() || connectionSettings.dir == "" {
		return fmt.Errorf("settings not initialized")
	}
	b, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(connectionSettings.dir, "preferences-*.tmp")
	if e != nil {
		return e
	}
	path := f.Name()
	defer os.Remove(path)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	from, _ := windows.UTF16PtrFromString(path)
	to, _ := windows.UTF16PtrFromString(filepath.Join(connectionSettings.dir, "connection-preferences.json"))
	if e = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	connectionSettings.p = p
	return nil
}
func ConnectionStartupEnabled() bool { return connectionPreferences().Startup }
func ShowConnectionSettings() {
	p := connectionPreferences()
	body := "iPad 通道：Windows 10.6.9.1 / iPad 10.6.9.3\r\nMac 通道：Windows 10.6.9.1 / Mac 10.6.9.2\r\n\r\n開機選項會在你登入 Windows 後自動啟動，等候接線。\r\n\r\nMac 與 iPad 會自動識別並準備 USB 網路，不需要選擇設備模式。USB 連線供本地通信，不共享網際網路。\r\niPad 詢問是否信任時，請點不信任。\r\n\r\n已記住的設備會比對 USB 廠商、產品、穩定識別資料及支援的介面布局，不再主動開啟蘋果配對會話。這是 USB 資料匹配，不是配對證書驗證。可清除記錄，恢復每次詢問。"
	checks := []PanelCheck{{Text: "登入 Windows 後自動啟動", Checked: p.Startup}, {Text: "清除已記住的設備（" + fmt.Sprint(len(p.USBDevices)) + " 台）"}}
	allowed, values := NativePanel("連線設定", body, "儲存設定", checks)
	if !allowed || len(values) != len(checks) {
		return
	}
	startupPreferenceMu.Lock()
	defer startupPreferenceMu.Unlock()
	p = connectionPreferences()
	old := p
	p.Startup, p.IndependentUSB = values[0], true
	if values[1] {
		p.Devices = nil
		p.USBDevices = nil
	}
	connectionSettings.Lock()
	setter := connectionSettings.startup
	connectionSettings.Unlock()
	if p.Startup != old.Startup {
		var e error
		if setter == nil {
			e = fmt.Errorf("STARTUP_SETTER_UNAVAILABLE")
		} else {
			e = setter(p.Startup)
		}
		RecordStartupSettingResult(e)
		if e != nil {
			NativePanel("設定尚未儲存", "無法更新開機啟動設定："+e.Error()+"。網路準備會繼續，請查看診斷。", "知道了", nil)
			return
		}
	}
	if saveConnectionPreferences(p) != nil {
		if setter != nil && p.Startup != old.Startup {
			setter(old.Startup)
		}
		NativePanel("設定尚未儲存", "無法寫入受保護的設定記錄，已嘗試恢復原啟動設定。", "知道了", nil)
		return
	}

}

type ConnectionAuthorization struct {
	Security               securitypolicy.DeviceVerdict `json:"usb_security_admission"`
	securityMu             sync.Mutex
	guardContext           context.Context
	guardCancel            context.CancelFunc
	guardStop              func()
	securityFailure        string
	HostFirewall           securitypolicy.Evidence `json:"host_firewall_configuration"`
	Remembered             bool                    `json:"remembered"`
	Automatic              bool                    `json:"automatically_allowed"`
	Proof                  PairedIdentity          `json:"device_proof"`
	FirstProof             *PairedIdentity         `json:"initial_device_proof,omitempty"`
	USBInfoMatched         bool                    `json:"usb_info_matched_not_cryptographic_authentication"`
	IdentityPolicy         string                  `json:"identity_policy,omitempty"`
	grantedRoot            string
	grantedUSB             ipadsession.USBDeviceGrant
	grantedDescriptor      usbDescriptorAttachment
	descriptorGrantContext context.Context
	InitialUSB             *Snapshot `json:"initial_usb_information,omitempty"`
	ConsentStatus          string    `json:"usb_consent_status,omitempty"`
	Once                   bool      `json:"allowed_this_connection"`
}

func (a *ConnectionAuthorization) Allow() bool {
	if a.guardContext == nil || a.guardContext.Err() != nil {
		a.ConsentStatus = "USB_DESCRIPTOR_CONNECTION_CONTEXT_REQUIRED"
		return false
	}
	s := Inspect()
	if a.InitialUSB == nil {
		a.InitialUSB = &s
	}
	if !networkOnlyUSBEligible(s) {
		a.ConsentStatus = "USB_PREFLIGHT_UNCONFIRMED"
		return false
	}
	binding := descriptorAttachment(s)
	model := binding.product // Verified real iProduct, never the display fallback.
	g := ipadsession.USBDescriptorGrant(binding.serial, model, "12AB", "photo-mux-cfg3-to-ncm-union-cfg5-v3")
	if !g.Valid() || !binding.verified {
		a.ConsentStatus = "USB_DESCRIPTOR_IDENTITY_UNCONFIRMED"
		return false
	}
	return a.allowUSB(model, binding.root, "12AB", func() string {
		fresh := Inspect()
		if !binding.same(descriptorAttachment(fresh)) {
			return ""
		}
		return exactIPadRoot(fresh)
	}, g, "USB_SERIAL_PRODUCT_DESCRIPTORS_NOT_APPLE_PAIRING", binding)
}

// Network authorization is deliberately independent of Apple's system trust.
// It does not contact usbmux/lockdown, read credentials or start a TLS session.
var usbConsentMu sync.Mutex // Short state access only; never held while waiting for a panel.
var usbConsent = newUSBConsentGate()

func (a *ConnectionAuthorization) AllowUSB(kind, root, pid, layout string, current func() string) (allowed bool) {
	// Existing Mac policy stays on its original instance-ID policy. iPad Allow
	// calls the private descriptor path and cannot silently reuse this grant.
	if pid == "12AB" {
		a.ConsentStatus = "USB_DESCRIPTOR_AUTHORIZATION_REQUIRED"
		return false
	}
	return a.allowUSB(kind, root, pid, current, ipadsession.USBGrant(root, pid, layout), "USB_IDENTIFIERS_NOT_APPLE_PAIRING", usbDescriptorAttachment{})
}

func (a *ConnectionAuthorization) allowUSB(kind, root, pid string, current func() string, g ipadsession.USBDeviceGrant, policy string, binding usbDescriptorAttachment) (allowed bool) {
	defer func() {
		usbConsentMu.Lock()
		defer usbConsentMu.Unlock()
		if allowed {
			a.watchSecurity(root)
		}
		target := connectionMonitor()
		if kind == "Mac" {
			target = deviceMonitor("Mac")
		}
		if s := target; s != nil {
			s.update(func(r *ApplicationResult) {
				r.PairedTLSAuthenticated = false
				r.DeviceAuthorization = "尚未允許"
				if allowed {
					a.ConsentStatus = "USB_ALLOWED"
					r.DeviceAuthorization = "只允許本次 USB 連線"
					if a.Remembered {
						r.DeviceAuthorization = "已記住 USB 資料，下次匹配後自動允許"
					}
					if a.Automatic {
						r.DeviceAuthorization = "USB 資料匹配，已自動允許"
					}
				}
			})
		}
	}()
	// Remembered devices must not wait behind another device's interactive
	// question (including a question pending before user logon). Each bypass
	// still checks this attempt, exact attachment, USB safety and saved consent.
	fresh := func() bool {
		if root == "" || current == nil || a.authorizationContext().Err() != nil {
			return false
		}
		if current() != root {
			a.ConsentStatus = "USB_DESCRIPTOR_OR_ATTACHMENT_CHANGED"
			return false
		}
		return a.checkSecurity(root) && a.authorizationContext().Err() == nil && current() == root
	}
	cached := func() (bool, bool) {
		usbConsentMu.Lock()
		defer usbConsentMu.Unlock()
		if !fresh() {
			return false, true
		}
		descriptorOnce := policy != "USB_SERIAL_PRODUCT_DESCRIPTORS_NOT_APPLE_PAIRING" || currentUSBDescriptorPermission(a.descriptorGrantContext, a.grantedDescriptor, binding)
		if a.Once && a.grantedRoot == root && a.grantedUSB == g && descriptorOnce {
			return fresh(), true
		}
		a.Proof = PairedIdentity{Error: "NOT_REQUESTED_USB_INFO_POLICY"}
		a.USBInfoMatched = g.Valid()
		a.IdentityPolicy = policy
		if !connectionPreferences().TrustedUSB(g) {
			return false, false
		}
		if !fresh() || !connectionPreferences().TrustedUSB(g) || a.authorizationContext().Err() != nil || current() != root {
			return false, true
		}
		a.Automatic, a.Remembered, a.Once = true, true, true
		a.grantedRoot, a.grantedUSB = root, g
		a.grantedDescriptor, a.descriptorGrantContext = binding, a.guardContext
		return true, true
	}
	return usbConsent.run(a.authorizationContext(), cached, func() bool {
		usbConsentMu.Lock()
		a.Automatic = false
		a.Remembered = false
		a.Once = false
		a.grantedRoot = ""
		a.grantedUSB = ipadsession.USBDeviceGrant{}
		a.grantedDescriptor, a.descriptorGrantContext = usbDescriptorAttachment{}, nil
		usbConsentMu.Unlock()
		body := "允許這台 " + kind + " 透過 USB 建立本地網路嗎？\r\n\r\n會準備專用 USB 網路及本次地址與限定防火牆規則。iPad 通道可能短暫暫停並恢復蘋果服務、切換網卡模式；Mac 通道可能準備 WinUSB 並遷移本程式擁有的舊版常駐服務。結束後清理本次網路設定。\r\n\r\nUSB Link 的允許與 iPad 的「信任此電腦」是兩件事。本程式不再開啟蘋果配對會話、不讀取照片、文件或備份。\r\n\r\n「記住」只匹配 USB 序列號、機型及支援的介面布局。USB 序列號可能被惡意設備偽造，並非配對證書驗證。USB 網關仍預設拒絕，僅放行你授權的應用；Moonlight／Sunshine 仍需 PIN 配對與證書驗證。"
		yes, values := NativePanelWithContext(a.authorizationContext(), "允許 USB 連線", body, "允許連線", []PanelCheck{{Text: "記住此 USB 設備，下次資料匹配時不再詢問", Disabled: !g.Valid()}})
		if !yes || a.authorizationContext().Err() != nil || current() != root {
			a.ConsentStatus = "USB_DECLINED_CANCELLED_OR_CHANGED"
			return false
		}
		if !fresh() {
			return false
		}
		usbConsentMu.Lock()
		a.Once = true
		a.grantedRoot = root
		a.grantedUSB = g
		a.grantedDescriptor, a.descriptorGrantContext = binding, a.guardContext
		usbConsentMu.Unlock()
		if len(values) == 1 && values[0] {
			p := connectionPreferences()
			if p.RememberUSB(g) && saveConnectionPreferences(p) == nil {
				usbConsentMu.Lock()
				a.Remembered = true
				usbConsentMu.Unlock()
			} else {
				NativePanel("本次連線已允許", "USB 記錄未能儲存，下次仍會詢問。", "知道了", nil)
			}
		}
		return true
	})
}

func SetMonitorDeviceKind(kind string) {
	if s := connectionMonitor(); s != nil {
		s.update(func(r *ApplicationResult) {
			*r = ApplicationResult{DeviceKind: kind, RemainingSeconds: -1}
			if kind == "Mac" {
				r.WindowsIPv4 = "10.6.9.1"
			} else {
				r.WindowsIPv4 = "10.6.9.1"
				r.ProposedIPadIPv4 = "10.6.9.3"
			}
		})
	}
}
func UpdateMacMonitor(m macconnection.Result) {
	if s := deviceMonitor("Mac"); s != nil {
		s.update(func(r *ApplicationResult) {
			applyMacBridgeDiagnostics(r, m)
			r.DeviceKind = "Mac"
			r.Status = m.Stage
			r.WindowsIPv4 = "10.6.9.1"
			r.MacPeerResolved = m.PeerResolved
			r.MacEffectiveMTU = m.EffectiveMTU
			r.MacPathMTUWarning = m.PathMTUWarning
			r.MacDHCPStarted = m.DHCPStarted
			r.MacDHCPDiscoveries, r.MacDHCPOffers, r.MacDHCPACKs = m.DHCPDiscoveries, m.DHCPOffers, m.DHCPACKs
			r.MacSunshineTCPObserved = m.SunshineTCPObserved
			r.TCPQueryError = m.TCPQueryError
			r.Traffic = m.Traffic
			r.ObservedTransmitMbps = m.Traffic.TransmitMbps
			r.ObservedReceiveMbps = m.Traffic.ReceiveMbps
			r.ElapsedSeconds = m.HeldSeconds
			r.MacBridgeDrops = m.BridgeDrops
			r.FileReceiverReady = m.FileReceiverReady
			r.Benchmark = m.Benchmark
			r.ShareReady = m.ShareReady
			r.ShareError = m.ShareError
			r.FilesReceived = m.FilesReceived
			r.FileBytes = m.FileBytes
			r.FileError = m.FileError
			r.Error = m.Error
			r.RuntimePreparationError = m.PreparationError
		})
	}
}
func OpenReceivedFiles() {
	dir, e := macconnection.ReceivedDirectory()
	if e != nil {
		NativePanel("接收資料夾尚未就緒", "請先完成 Mac USB 連線。", "知道了", nil)
		return
	}
	windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(dir), nil, nil, 1)
}

// Remote diagnostics omit device identifiers and pairing material.
func ConnectionRuntimeStatus() (string, string) {
	if s := selectedDeviceMonitor(); s != nil {
		r := s.snapshot()
		return r.Status, r.Error
	}
	return "MONITOR_UNAVAILABLE", ""
}

func RemoteUSBConnectionHealthy() bool {
	if s := deviceMonitor("Mac"); s != nil {
		r := s.snapshot()
		if r.Error != "" || r.DHCPError != "" {
			return false
		}
		if r.Status == "MAC_RUNNING" {
			return macconnection.RemoteReady(r.MacPeerResolved, r.FileReceiverReady, r.FileError)
		}
		return r.Status == "USB_APPLICATION_TRIAL_RUNNING" && r.PeerIPv4NeighborVerified
	}
	return false
}

func (a *ConnectionAuthorization) authorizationContext() context.Context {
	if a.guardContext != nil {
		return a.guardContext
	}
	return connectionContext()
}
