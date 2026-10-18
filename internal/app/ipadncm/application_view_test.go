package ipadncm

import (
	"strings"
	"testing"
)

func TestApplicationUIProofLevels(t *testing.T) {
	r := ApplicationResult{Status: "USB_APPLICATION_TRIAL_RUNNING", WindowsIPv4: "10.77.42.1", DHCPStarted: true, DHCPACKs: 1, MDNSRegistered: true, SunshineUSBLocalHTTP: true}
	title, ip, detail := applicationView(r, false)
	if ip != r.WindowsIPv4 || strings.Contains(title, "已驗證") || !strings.Contains(detail, "仍需確認 iPad 使用地址") || !strings.Contains(detail, "是否出現在 Moonlight 仍待確認") {
		t.Fatal(title, detail)
	}
	r.DeviceKind = "iPad"
	r.PeerIPv4NeighborVerified = true
	title, _, detail = applicationView(r, false)
	if title != "iPad USB 已連接" || connectionSubtitle(r) != "iPad · USB 已連接" || !strings.Contains(detail, "已確認 iPad 使用 USB 地址") || strings.Contains(detail, "等候 iPad 連接") || !strings.Contains(detail, "尚未觀察到 iPad 與 Sunshine 的 TCP 連線") || r.MoonlightVerified || r.NetworkVerified {
		t.Fatal(title, detail)
	}
	r.PeerIPv4NeighborVerified = false
	r.HTTPVerified = true
	title, _, _ = applicationView(r, false)
	if !strings.Contains(title, "IPv4 通信已驗證") {
		t.Fatal(title)
	}
	r.SunshineClientTCPObserved = true
	title, _, detail = applicationView(r, false)
	if !strings.Contains(title, "請嘗試串流") || !strings.Contains(detail, "串流仍需確認") {
		t.Fatal(title, detail)
	}
	r.UserReportsStream = true
	title, _, _ = applicationView(r, false)
	if !strings.Contains(title, "你回報") || r.MoonlightVerified || r.NetworkVerified {
		t.Fatal(title)
	}
	title, _, _ = applicationView(r, true)
	if !strings.Contains(title, "恢復設定") {
		t.Fatal(title)
	}
	r.Error = "FAIL"
	title, _, _ = applicationView(r, true)
	if !strings.Contains(title, "診斷") {
		t.Fatal(title)
	}
}

func TestApplicationUIUnassignedAddressAndCounters(t *testing.T) {
	_, ip, detail := applicationView(ApplicationResult{RemainingSeconds: 0, ObservedTransmitMbps: 123.4}, false)
	if ip != "正在準備地址" || !strings.Contains(detail, "剩餘約 0 分鐘") || !strings.Contains(detail, "123.4 Mbps") || !strings.Contains(detail, "不是線路最高頻寬") {
		t.Fatal(ip, detail)
	}
}

func TestPersistentTelemetryDoesNotClaimBandwidthOrLatency(t *testing.T) {
	r := ApplicationResult{Status: "MONITOR_WAITING", RemainingSeconds: -1, WindowsIPv4: "10.6.9.1", USBSpeed: "USB SuperSpeed（5 Gbps 級別）"}
	r.Traffic.SentBytes = 1000000000
	r.Traffic.PeakTransmitMbps = 401.2
	title, ip, d := applicationView(r, false)
	if title != "等候 USB 接線" || ip != "10.6.9.1" || strings.Contains(d, "20 分鐘") || !strings.Contains(d, "401.2") || !strings.Contains(d, "1.00 GB") || !strings.Contains(d, "未報告") || !strings.Contains(d, "不是線路最高頻寬") {
		t.Fatal(title, d)
	}
	r.SunshineClientTCPObserved = true
	r.TCPAddressFamily = "IPv6"
	_, _, d = applicationView(r, false)
	if !strings.Contains(d, "USB IPv6 TCP") || strings.Contains(d, "USB IPv4 TCP") {
		t.Fatal(d)
	}
}

func TestPausedConnectionOffersExplicitRetryAndPreservesFailure(t *testing.T) {
	title, _, detail := applicationView(ApplicationResult{Status: "MONITOR_PAUSED", Error: "EXACT_ROOT_REENUMERATION_TIMEOUT"}, false)
	if !strings.Contains(title, "重試連線") || !strings.Contains(detail, "EXACT_ROOT_REENUMERATION_TIMEOUT") || !strings.Contains(detail, "未執行 USB 初始化") {
		t.Fatal(title, detail)
	}
}

func TestMissingAppleDeviceDoesNotClaimTrustWasDenied(t *testing.T) {
	_, _, d := applicationView(ApplicationResult{Status: "MONITOR_PAUSED", Error: "APPLE_USB_DEVICE_NOT_READY"}, false)
	if !strings.Contains(d, "蘋果通信尚未就緒") || !strings.Contains(d, "重試連線") || strings.Contains(d, "你拒絕了信任") {
		t.Fatal(d)
	}
}

func TestInterfaceCountersAreNotPresentedAsMoonlightLoss(t *testing.T) {
	r := ApplicationResult{MTU: 1500}
	r.Performance.Samples = 1
	r.Performance.Faults.OutDiscards = 15
	_, _, d := applicationView(r, false)
	if !strings.Contains(d, "傳送丟棄 15") || !strings.Contains(d, "不代表 Moonlight 丟包率") || !strings.Contains(d, "MTU：1500") {
		t.Fatal(d)
	}
}

func TestPausedMacRetainsRuntimePreparationDetail(t *testing.T) {
	_, _, detail := applicationView(ApplicationResult{DeviceKind: "Mac", Status: "MONITOR_PAUSED", Error: "MAC_EMBEDDED_RUNTIME_PREPARATION_FAILED", RuntimePreparationError: "existing asset changed: suhang-usbnet.exe"}, false)
	if !strings.Contains(detail, "existing asset changed: suhang-usbnet.exe") {
		t.Fatal("paused view lost concrete preparation error")
	}
}

func TestRecoveryUIIsNotPresentedAsWorkingNetwork(t *testing.T) {
	for _, kind := range []string{"Mac", "iPad"} {
		r := ApplicationResult{DeviceKind: kind, Status: "USB_RECOVERY_MAINTENANCE", Error: "RESTORE_PENDING", ServicesReady: true, DHCPStarted: true}
		title, ip, detail := applicationView(r, false)
		if title != "USB 恢復維護" || ip == "10.6.9.1" || strings.Contains(detail, "/upload") || !strings.Contains(detail, "RESTORE_PENDING") || !strings.Contains(connectionSubtitle(r), "恢復維護") {
			t.Fatal(title, ip, detail)
		}
	}
}

func TestIPadPeerProofDoesNotOverridePausedOrDisconnectedState(t *testing.T) {
	for _, status := range []string{"MONITOR_WAITING", "MONITOR_PAUSED", "MONITOR_RETRYING", "USB_RECOVERY_MAINTENANCE", "WAITING_SHARED_HOST"} {
		r := ApplicationResult{DeviceKind: "iPad", Status: status, PeerIPv4NeighborVerified: true}
		title, _, _ := applicationView(r, false)
		if title == "iPad USB 已連接" || connectionSubtitle(r) == "iPad · USB 已連接" {
			t.Fatal(status, title)
		}
	}
}

func TestIPadWaitingViewHintsUSBRestrictedMode(t *testing.T) {
	_, _, d := applicationView(ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_WAITING", RemainingSeconds: -1}, false)
	if !strings.Contains(d, "USB 受限模式") || !strings.Contains(d, "解鎖 iPad") || !strings.Contains(d, "資料傳輸") {
		t.Fatal(d)
	}
	_, _, d = applicationView(ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_PAUSED", RemainingSeconds: -1}, false)
	if strings.Contains(d, "USB 受限模式") {
		t.Fatal("hint only while waiting for a device")
	}
}
