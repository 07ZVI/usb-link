//go:build windows && amd64

package ipadncm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/startuptelemetry"
	"suhang/usbnet/internal/app/uistartup"
	"suhang/usbnet/internal/dependencies"
	"suhang/usbnet/internal/diagnostics/throughput"
	"sync"
	"syscall"
	"time"
)

var productVersion string

func SetProductVersion(v string) { productVersion = v }

var desktopLauncher func() (string, error)

// The main executable supplies embedded bytes; there is no external download
// or path supplied by the UI or the network.
func SetDesktopLauncher(f func() (string, error)) { desktopLauncher = f }

type modernUI struct {
	mu                sync.Mutex
	ctx               context.Context
	state             *applicationState
	cancel            context.CancelFunc
	cmd               *exec.Cmd
	input             io.WriteCloser
	messages          chan any
	notice            string
	startupBusy       bool
	startupRequested  bool
	startupRequestID  string
	startupRejectedID string
	startupDone       chan struct{}
	lifetime          context.Context
	endUI             context.CancelFunc
	childDone         <-chan struct{}
	stopStarted       time.Time
	gatewayWatcher    sync.Once
	serviceOwner      bool
	refresh           chan struct{}
}

func (u *modernUI) show(reason string) bool {
	started := time.Now()
	var nonce [16]byte
	request := ""
	if _, err := rand.Read(nonce[:]); err == nil {
		request = hex.EncodeToString(nonce[:])
	}
	recordDesktopOpenTiming(request, "show-request", started)
	recordUIEvent(reason, "show-request", 0)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ctx.Err() != nil || desktopLauncher == nil {
		return false
	}
	if u.cmd != nil {
		select {
		case u.messages <- map[string]string{"event": "show"}:
			recordDesktopOpenTiming(request, "existing-renderer-show-queued", started)
		default:
		}
		u.requestRefresh()
		return true
	}
	path, e := desktopLauncher()
	if e != nil {
		u.notice = "新介面驗證失敗，已使用備用視窗。"
		return false
	}
	recordDesktopOpenTiming(request, "payload-verified", started)
	runtimeRoot, runtimeError := dependencies.Ensure(u.lifetime, "dotnet")
	if runtimeError != nil {
		u.notice = runtimeError.Error()
		return false
	}
	cmd := exec.CommandContext(u.lifetime, path)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "DOTNET_ROOT=") && !strings.HasPrefix(strings.ToUpper(entry), "DOTNET_ROOT_X64=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "DOTNET_ROOT="+runtimeRoot, "DOTNET_ROOT_X64="+runtimeRoot)
	cmd.Dir = filepath.Dir(path)
	stderr := &desktopErrorBuffer{}
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	in, e := cmd.StdinPipe()
	if e != nil {
		return false
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		in.Close()
		return false
	}
	if e = cmd.Start(); e != nil {
		in.Close()
		out.Close()
		return false
	}
	recordUIEvent(reason, "renderer-started", cmd.Process.Pid)
	recordDesktopOpenTiming(request, "renderer-started", started)
	u.cmd, u.input = cmd, in
	messages := make(chan any, 4)
	u.messages = messages
	childDone := make(chan struct{})
	u.childDone = childDone
	if currentServiceUIProxy() == nil {
		u.watchGateway()
	}
	ready := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-childDone:
				return
			case m := <-messages:
				if json.NewEncoder(in).Encode(m) != nil {
					return
				}
			}
		}
	}()
	go func() {
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 4096), 32768)
		for scanner.Scan() {
			var v desktopRequest
			if json.Unmarshal(scanner.Bytes(), &v) == nil {
				if v.Action == "renderer-stage" {
					if validRendererStage(v.ID) {
						recordDesktopOpenTiming(request, v.ID, started)
					}
					continue
				}
				if v.Action == "ready" {
					recordDesktopOpenTiming(request, "renderer-opened", started)
					select {
					case ready <- struct{}{}:
					default:
					}
					continue
				}
				if v.Action == "update-notice-shown" {
					acknowledgeUpdateNotice(u, cmd.Process.Pid, v.ID)
					continue
				}
				if !u.proxyAction(v) && !u.shareFoldersAction(v) && !u.gatewayAction(v) && !u.securityAction(v) {
					if v.Action == "startup-on" || v.Action == "startup-off" {
						u.startupAction(v.Action, v.ID)
					} else {
						u.action(v.Action)
					}
				}
			}
		}
		waitErr := cmd.Wait()
		recordUIEvent(reason, "renderer-exited", cmd.Process.Pid)
		if waitErr != nil && u.ctx.Err() == nil {
			u.state.update(func(r *ApplicationResult) {
				r.DesktopError = fmt.Sprintf("DESKTOP_EXIT: %v: %s", waitErr, stderr.String())
			})
		}
		close(childDone)
		in.Close()
		out.Close()
		u.mu.Lock()
		if u.cmd == cmd {
			u.cmd = nil
			u.input = nil
		}
		u.mu.Unlock()
	}()
	select {
	case <-ready:
		u.requestRefresh()
		if currentServiceUIProxy() == nil {
			go u.replayGatewayRequests()
		}
		return true
	case <-childDone:
		return false
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		u.state.update(func(r *ApplicationResult) { r.DesktopError = "DESKTOP_READY_TIMEOUT" })
		return false
	}
}

// Request IDs only correlate display updates; they grant no system authority.
func (u *modernUI) startupAction(a, id string) {
	if a != "startup-on" && a != "startup-off" {
		return
	}
	if id != "" && !validStartupDisplayRequestID(id) {
		return
	}
	u.mu.Lock()
	if u.startupBusy || u.ctx.Err() != nil {
		// Keep the active request's identity. Retain this rejection in status
		// so a dropped immediate update cannot strand the renderer's latch.
		u.startupRejectedID = id
		u.mu.Unlock()
		u.push()
		return
	}
	u.startupBusy = true
	u.startupRequested = a == "startup-on"
	u.startupRequestID = id
	done := make(chan struct{})
	u.startupDone = done
	u.notice = "正在核對開機啟動設定…"
	u.mu.Unlock()
	u.push()
	go func() {
		defer close(done)
		e := setModernPreference(a)
		RecordStartupSettingResult(e)
		u.mu.Lock()
		u.startupBusy = false
		if e != nil {
			u.notice = "開機啟動設定未完成：" + e.Error() + "。請查看連線診斷。"
		} else {
			u.notice = "開機啟動設定已儲存並核對。"
		}
		u.mu.Unlock()
		u.push()
	}()
}

func validStartupDisplayRequestID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (u *modernUI) action(a string) {
	if u.ctx.Err() != nil {
		return
	}
	switch a {
	case "select-mac":
		selectDevice("Mac")
	case "select-ipad":
		selectDevice("iPad")
	case "share-on", "share-off":
		go func() {
			shareFoldersBusy.Lock()
			defer shareFoldersBusy.Unlock()
			u.setNotice("正在更新 Windows SMB 共享…")
			if e := connectioninstall.SetNativeSMB(a == "share-on"); e != nil {
				u.setNotice("Windows SMB 設定未完成：" + e.Error())
			} else if a == "share-on" {
				u.setNotice("Windows SMB 共享已開啟，退出程式後保留；請使用顯示的帳戶或已啟用的訪客。")
			} else {
				u.setNotice("已關閉程式管理的 Windows 共享，檔案保留。")
			}
		}()
	case "open-share":
		dir, e := connectioninstall.SharedDirectory()
		if e != nil {
			u.setNotice("無法開啟共享資料夾。")
			return
		}
		windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(dir), nil, nil, 1)
	case "ipad-revoke-trust":
		go func() {
			result, err := ConfirmAndRevokeCurrentComputerTrust()
			if err != nil {
				if result.Notice != "" {
					u.setNotice(result.Notice)
				} else {
					u.setNotice("撤銷本機信任未完成；檔案與操作記錄保留，請查看診斷。")
				}
				return
			}
			u.setNotice(result.Notice)
		}()
	case "startup-on", "startup-off":
		u.startupAction(a, "")
	case "settings":
		if u.state.Settings != nil {
			go u.state.Settings()
		}
	case "received":
		go OpenReceivedFiles()
	case "retry", "retry-mac", "retry-ipad":
		kind := map[string]string{"retry-mac": "Mac", "retry-ipad": "iPad"}[a]
		retried := desktopRetryDevices(deviceDisplaySnapshots(), kind, func(device string) {
			if device == "Mac" {
				requestMacRetry()
			} else {
				requestConnectionRetry()
			}
		})
		if !retried {
			u.setNotice("目前無需重試；連線仍在運行或等候裝置。")
		}
	case "developer-on", "developer-off":
		go func() {
			if remoteEnable == nil {
				detail := "開發者調試無法啟動。"
				if remoteInfo != nil {
					detail, _ = remoteInfo()
				}
				u.setNotice(detail)
				return
			}
			if e := remoteEnable(a == "developer-on"); e != nil {
				u.setNotice("開發者調試設定失敗：" + e.Error())
			} else {
				u.setNotice("開發者調試設定已更新。")
			}
		}()
	case "auto-upgrade-on", "auto-upgrade-off":
		go func() {
			if remoteSetAutoUpgrade == nil {
				u.setNotice("USB 自動升級暫時無法使用。")
				return
			}
			if e := remoteSetAutoUpgrade(a == "auto-upgrade-on"); e != nil {
				u.setNotice("自動升級設定未儲存：" + e.Error())
				return
			}
			if a == "auto-upgrade-on" {
				u.setNotice("已允許 USB 自動升級；收到新版和開始安裝時會顯示提示並播放提示音。")
			} else {
				u.setNotice("已關閉自動升級；每次安裝前會彈窗確認。")
			}
		}()
	case "benchmark-start":
		if e := throughput.DeviceCurrent("Mac").StartNative(); e != nil {
			u.setNotice(e.Error())
		} else {
			u.setNotice("已開始主動雙向測速。")
		}
	case "benchmark-cancel":
		throughput.DeviceCurrent("Mac").CancelNative()
	case "stop":
		u.cancel()
		u.push()
	}
}
func (u *modernUI) setNotice(s string) { u.mu.Lock(); u.notice = s; u.mu.Unlock() }

// Wake the existing status worker after opening; avoid a full polling interval
// with a stale waiting screen, without adding concurrent snapshot readers.
func (u *modernUI) requestRefresh() {
	select {
	case u.refresh <- struct{}{}:
	default:
	}
}
func (u *modernUI) run() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-u.lifetime.Done():
			return
		case <-t.C:
			u.push()
		case <-u.refresh:
			u.push()
		}
	}
}
func (u *modernUI) push() {
	if proxy := currentServiceUIProxy(); proxy != nil {
		u.proxyPush(proxy)
		return
	}
	u.mu.Lock()
	connected := u.input != nil
	u.mu.Unlock()
	if !connected && !backgroundUIBaseline.Load() {
		return
	}

	u.publishStatus(u.desktopStatus())
}

func (u *modernUI) publishStatus(status any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.input == nil {
		return
	}
	select {
	case u.messages <- status:
	default:
	}
}

func (u *modernUI) desktopStatus() any {
	r := u.state.snapshot()
	autoUpgrade := remoteAutoUpgrade != nil && remoteAutoUpgrade()
	developerEnabled := false
	if remoteEnabled != nil {
		developerEnabled = remoteEnabled()
	}
	remoteStatus, remoteInvite := "開發者調試未啟動", ""
	if remoteInfo != nil {
		remoteStatus, remoteInvite = remoteInfo()
	}
	stopping := u.ctx.Err() != nil
	nativeShare := connectioninstall.NativeSMBStatus()
	ipadPolicy := SimplifiedIPadNetworkSnapshot()
	u.mu.Lock()
	defer u.mu.Unlock()
	if stopping {
		if u.stopStarted.IsZero() {
			u.stopStarted = time.Now()
		}
		u.notice = fmt.Sprintf("正在結束 USB 連線並恢復設定 · 已等候 %d 秒", int(time.Since(u.stopStarted).Seconds()))
	}
	status := desktopDeviceStatus(r, stopping)
	for k, v := range map[string]any{"event": "status", "connections": deviceSummary(), "version": productVersion, "stopping": stopping, "share_url": connectioninstall.NativeSMBServerURL, "native_smb": true, "native_account": nativeShare.Username, "share_problem": nativeShare.Problem, "share_ready": nativeShare.Ready, "share_enabled": nativeShare.Enabled, "notice": u.notice, "startup": ConnectionStartupEnabled(), "startup_busy": u.startupBusy, "startup_requested": u.startupRequested, "startup_request_id": u.startupRequestID, "startup_rejected_id": u.startupRejectedID, "remote_auto_upgrade": autoUpgrade, "remote_enabled": developerEnabled, "remote_status": remoteStatus, "remote_invite": remoteInvite, "independent": connectionPreferences().IndependentUSB, "ipad_network_policy": ipadPolicy} {
		status[k] = v
	}
	devices := make([]map[string]any, 0, 2)
	var details string
	for _, snapshot := range deviceDisplaySnapshots() {
		if deviceMonitor(snapshot.DeviceKind) == nil && r.DeviceKind == snapshot.DeviceKind {
			snapshot = r
		}
		slot := desktopDeviceStatus(snapshot, stopping)
		devices = append(devices, slot)
		details += snapshot.DeviceKind + " USB\r\n" + slot["detail"].(string) + "\r\n\r\n"
		delete(slot, "detail") // The shared diagnostics field carries both full reports.
	}
	status["devices"] = devices
	status["detail"] = details + "啟動與安全\r\n" + startupTimingText(startuptelemetry.Snapshot()) + "\r\n安全檢查：" + securitySummary()
	if problem := StartupSettingProblem(); problem != "" {
		status["detail"] = status["detail"].(string) + "\r\n開機啟動設定：" + problem
	}
	if r.Status == "WAITING_SHARED_HOST" {
		b, _ := json.Marshal(sharedHostWaitingDiagnostics())
		status["detail"] = status["detail"].(string) + "\r\n共享網卡準備：" + string(b)
	}
	return status
}

func setModernPreference(action string) error {
	return setModernStartupPreference(action, false)
}

func setModernStartupPreference(action string, verifyUnchanged bool) error {
	startupPreferenceMu.Lock()
	defer startupPreferenceMu.Unlock()
	p := connectionPreferences()
	old := p
	connectionSettings.Lock()
	setter := connectionSettings.startup
	connectionSettings.Unlock()
	switch action {
	case "startup-on":
		p.Startup = true
	case "startup-off":
		p.Startup = false
	default:
		return fmt.Errorf("STARTUP_ACTION_INVALID")
	}
	apply := p.Startup != old.Startup || verifyUnchanged
	if apply {
		if setter == nil {
			return fmt.Errorf("STARTUP_SETTER_UNAVAILABLE")
		}
		if e := setter(p.Startup); e != nil {
			return e
		}
	}
	if e := saveConnectionPreferences(p); e != nil {
		if setter != nil && apply {
			if rollback := setter(old.Startup); rollback != nil {
				return fmt.Errorf("STARTUP_PREFERENCES_SAVE_AND_ROLLBACK_FAILED: %w", rollback)
			}
		}
		return fmt.Errorf("STARTUP_PREFERENCES_SAVE_FAILED")
	}
	return nil
}

type desktopErrorBuffer struct{ bytes.Buffer }

func (b *desktopErrorBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if left := 4096 - b.Len(); left > 0 {
		b.Buffer.Write(p[:min(n, left)])
	}
	return n, nil
}

// Keep the renderer alive while network cleanup runs. Only the UI owner calls
// close after cleanup; an unresponsive owned renderer has a bounded exit.
func (u *modernUI) close() {
	u.mu.Lock()
	done := u.childDone
	startupDone := u.startupDone
	if u.messages != nil {
		select {
		case u.messages <- map[string]string{"event": "shutdown"}:
		default:
		}
	}
	u.mu.Unlock()
	// Parent cancellation terminates the owned startup command. Join before
	// the main process releases its owner/handoff lock to a newer installer.
	if startupDone != nil {
		<-startupDone
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	u.endUI()
}

// Renderer markers grant no action or readiness authority. Older verified
// desktop components omit them; the existing ready gate is unchanged.
func validRendererStage(stage string) bool { return uistartup.RendererStage(stage) }
