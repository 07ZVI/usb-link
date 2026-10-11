package ipadncm

import "fmt"

func applicationView(r ApplicationResult, stopping bool) (title, ip, detail string) {
	if r.Status == "USB_RECOVERY_MAINTENANCE" || r.Status == "USB_RECOVERY_WAITING" {
		return "USB 恢復維護", "正常網路尚未就緒", "正在保留 USB 診斷及修復升級通道。開啟設定中的開發者調試，並保持 Mac 接線。\r\n此模式不轉發一般網路流量；目前不能串流、分享檔案或測速。\r\n恢復記錄保留，確認完成後才重新啟用一般連線。\r\n\r\n狀態：" + r.Error
	}
	if r.DeviceKind == "Mac" {
		return macApplicationView(r, stopping)
	}
	title = "正在準備 iPad 的 USB 連線…"
	if r.Status == "MONITOR_WAITING" {
		title = "等候 USB 接線"
	}
	if r.Status == "MONITOR_PREPARING" {
		title = "正在驗證設備並準備連線…"
	}
	if r.Status == "WAITING_SHARED_HOST" {
		title = "正在等候共享網卡 · 將自動繼續"
	}
	if r.Status == "MONITOR_PAUSED" {
		title = "連線暫停 · 可查看原因或按「重試連線」"
		if r.Error == "APPLICATION_SHARED_HOST_UNAVAILABLE" {
			title = "正在等候共享網卡 · 將自動繼續"
		}
	}
	if r.Status == "IPAD_WAITING_PEER_ADDRESS" {
		title = "正在等候 iPad 網路地址就緒…"
	}
	if r.Status == "MONITOR_RETRYING" {
		title = fmt.Sprintf("正在自動恢復連線 · %d 秒後重試（%d/3）", r.AutoRetrySeconds, r.AutoRetryAttempt)
	}
	if r.Status == "USB_APPLICATION_TRIAL_RUNNING" {
		title = "USB 網卡已啟動，等候 iPad 連接"
		if r.PeerIPv4NeighborVerified {
			title = "iPad USB 已連接"
		}
		if r.SunshineClientTCPObserved || r.HTTPVerified {
			title = "iPad 的 USB IPv4 通信已驗證"
		}
		if r.SunshineClientTCPObserved {
			title = "已觀察到 iPad 連到 Sunshine，請嘗試串流"
		}
		if r.UserReportsStream {
			title = "已記錄：你回報畫面、聲音和操作正常"
		}
	}
	if stopping || r.Status == "APPLICATION_TRIAL_ENDED_RESTORING" {
		title = "正在結束連線、恢復設定，請稍候…"
	}
	if r.Error != "" && ((r.Status != "MONITOR_PAUSED" && r.Status != "MONITOR_RETRYING") || stopping) {
		title = "連線檢查遇到問題，請等候恢復及診斷資料"
	}
	ip = r.WindowsIPv4
	if ip == "" {
		ip = "正在準備地址"
	}
	allocation := "等候 iPad 的地址請求"
	if !r.DHCPStarted {
		allocation = "正在準備地址分配"
	} else if r.DHCPACKs > 0 {
		allocation = "分配回覆已送出；仍需確認 iPad 使用地址"
	} else if r.DHCPOffers > 0 {
		allocation = "已提供地址，等候 iPad 確認"
	}
	if r.PeerIPv4NeighborVerified {
		allocation = "已確認 iPad 使用 USB 地址"
	}
	if r.DHCPDeclined {
		allocation = "iPad 拒絕此地址，本輪已停止"
	}
	proof := "尚未驗證 IPv4 往返"
	if r.PeerIPv4NeighborVerified {
		proof = "iPad 的 USB IPv4 地址及設備身分已驗證"
	}
	if r.SunshineClientTCPObserved {
		proof = "USB " + r.TCPAddressFamily + " TCP 連接已觀察到"
	} else if r.HTTPVerified {
		proof = "iPad Safari 的 USB 網頁往返已通過"
	}
	sun := "尚未在預設連接埠確認 Sunshine，請確認它正在執行"
	if r.SunshineUSBLocalHTTP {
		sun = "Windows 本機服務檢查成功"
	} else if r.SunshineLoopbackHTTP {
		sun = "本機服務已執行，但 USB 地址上的檢查未通過"
	}
	discovery := "尚未就緒；可在 Moonlight 手動新增上方 IP"
	if r.MDNSRegistered {
		discovery = "已發佈電腦；是否出現在 Moonlight 仍待確認"
	}
	client := "尚未觀察到 iPad 與 Sunshine 的 TCP 連線"
	if r.SunshineClientTCPObserved {
		client = "已觀察到 iPad 經 USB 連到 Sunshine；串流仍需確認"
	}
	usb := r.USBSpeed
	if usb == "" {
		usb = "尚未取得目前 USB 協商級別"
	}
	tx, rx := "未報告", "未報告"
	if r.ReportedTransmitBPS > 0 {
		tx = fmt.Sprintf("%.0f Mbps", float64(r.ReportedTransmitBPS)/1e6)
	}
	if r.ReportedReceiveBPS > 0 {
		rx = fmt.Sprintf("%.0f Mbps", float64(r.ReportedReceiveBPS)/1e6)
	}
	gateway := "未提供本地閘道"
	if r.RouterAdvertised {
		gateway = "本地 USB 閘道已啟用；不共享網際網路"
	}
	duration := "持續保持連線；最小化後仍運行"
	if r.RemainingSeconds >= 0 {
		duration = fmt.Sprintf("本輪剩餘約 %d 分鐘", (r.RemainingSeconds+59)/60)
	}
	echo := "尚無有效回聲數據"
	if r.EchoSamples > 0 {
		echo = fmt.Sprintf("USB 啟動回聲 %d–%d ms（%d 次；API 整數精度，非串流延遲）", r.EchoMinMilliseconds, r.EchoMaxMilliseconds, r.EchoSamples)
	}
	detail = fmt.Sprintf("設備授權：%s\r\n地址分配：%s\r\niPad 候選地址：%s\r\n通信驗證：%s\r\nSunshine：%s\r\n自動發現：%s\r\n應用連接：%s\r\n\r\nUSB 協商級別：%s\r\n網卡回報：傳送 %s / 接收 %s（未報告時不填 0 或推算）\r\n目前 Windows → iPad：%.1f Mbps\r\n目前 iPad → Windows：%.1f Mbps\r\n峰值：傳送 %.1f / 接收 %.1f Mbps\r\n累計：傳送 %s / 接收 %s\r\n這是介面收發流量，不是線路最高頻寬。\r\n%s\r\n串流端到端延遲尚未測量。\r\n\r\n%s\r\n連線時間：%d 分 %02d 秒\r\n%s\r\n\r\n在 Moonlight 新增上方 IP，首次依 Sunshine 的 PIN 完成配對。\r\n若連不上，可在 Safari 開啟 http://%s:10690/ 驗證 USB。\r\n關閉 Wi-Fi 後首次連接仍須實測，不能只憑續流判定已解決。", r.DeviceAuthorization, allocation, r.ProposedIPadIPv4, proof, sun, discovery, client, usb, tx, rx, r.ObservedTransmitMbps, r.ObservedReceiveMbps, r.Traffic.PeakTransmitMbps, r.Traffic.PeakReceiveMbps, formatTransfer(r.Traffic.SentBytes), formatTransfer(r.Traffic.ReceivedBytes), echo, duration, r.ElapsedSeconds/60, r.ElapsedSeconds%60, gateway, ip)
	if r.Performance.Samples > 0 {
		detail += fmt.Sprintf("\r\n\r\nWindows USB 介面計數（本輪）：\r\n傳送丟棄 %d / 接收丟棄 %d；傳送錯誤 %d / 接收錯誤 %d\r\n計數器重置 %d 次；不代表 Moonlight 丟包率或解碼掉幀。\r\nMTU：%d；串流期間設備檢查使用系統快取，不讀取 USB 描述符。\r\n設備查詢最長 %.1f ms；取樣間隔最長 %.1f ms（均非封包延遲）。", r.Performance.Faults.OutDiscards, r.Performance.Faults.InDiscards, r.Performance.Faults.OutErrors, r.Performance.Faults.InErrors, r.Performance.FaultCounterResets, r.MTU, r.Performance.MaxQueryMS, r.Performance.MaxIntervalMS)
	}
	if r.Status == "MONITOR_WAITING" || r.Status == "MONITOR_PAUSED" || r.Status == "WAITING_SHARED_HOST" {
		detail = "目前未執行 USB 初始化或網路配置。下方數據保留上一輪結果，並非目前連線。\r\n\r\n" + detail
	}
	if r.Error != "" {
		detail = "停止原因：" + r.Error + "\r\n\r\n" + detail
	}
	if r.Error == "APPLE_USB_DEVICE_NOT_READY" {
		detail = "蘋果通信尚未就緒。程式會對暫時性失敗自動重試；請保持連接並解鎖 iPad。若自動重試已用完，可在設備就緒後按「重試連線」。\r\n\r\n" + detail
	}
	if r.Error == "APPLICATION_SHARED_HOST_UNAVAILABLE" {
		detail = "Windows 的共享網路地址 10.6.9.1 尚未就緒，程式會在背景自動準備，完成後繼續連線；不需要重開程式。\r\n此問題與是否點選「信任」無關；不會改用其他地址。\r\n\r\n" + detail
	}
	if r.Status == "WAITING_SHARED_HOST" {
		detail = "共享網路正在背景準備；完成後會自動繼續，不需要按重試或重開程式。\r\n\r\n" + detail
	}
	return
}
func formatTransfer(n uint64) string {
	if n >= 1e9 {
		return fmt.Sprintf("%.2f GB", float64(n)/1e9)
	}
	if n >= 1e6 {
		return fmt.Sprintf("%.1f MB", float64(n)/1e6)
	}
	return fmt.Sprintf("%.1f KB", float64(n)/1e3)
}

func macApplicationView(r ApplicationResult, stopping bool) (title, ip, detail string) {
	if r.Status == "WAITING_SHARED_HOST" {
		return "正在等候共享網卡 · 將自動繼續", "10.6.9.1", "程式會在背景自動準備共享網路，完成後繼續 Mac USB 連線；不需要重開程式。"
	}
	title = "正在準備 Mac USB 連線…"
	ip = r.WindowsIPv4
	if r.Status == "MAC_RUNNING" {
		title = "Mac USB 網路已啟動"
	}
	if r.MacPeerResolved {
		title = "已識別 Mac USB 網路對端"
	}
	if r.Status == "MONITOR_WAITING" {
		title = "等候 USB 接線"
	}
	if r.Status == "MONITOR_PAUSED" {
		title = "連線暫停 · 可查看原因或按「重試連線」"
	}
	if r.Status == "MONITOR_RETRYING" {
		title = fmt.Sprintf("正在自動恢復連線 · %d 秒後重試（%d/3）", r.AutoRetrySeconds, r.AutoRetryAttempt)
	}
	if stopping {
		title = "正在結束並清理 Mac USB 連線…"
	}
	files := "尚未就緒"
	if r.FileReceiverReady {
		files = "已開放；只接收這條 USB 的 Mac，接收後不會執行檔案"
	}
	proof := "尚未觀察到 Mac 經 USB 連到 Sunshine"
	if r.MacSunshineTCPObserved {
		proof = "已觀察到 Mac 經 USB 連到 Sunshine；串流品質仍須實測"
	}
	detail = fmt.Sprintf("設備授權：%s\r\nWindows：10.6.9.1 / Mac：10.6.9.2\r\n自動分配：請求 %d / 提供 %d / 確認 %d（確認不代表已套用）\r\n應用連接：%s\r\n\r\n目前電腦 → Mac：%.1f Mbps\r\n目前 Mac → 電腦：%.1f Mbps\r\n峰值：傳送 %.1f / 接收 %.1f Mbps\r\n累計：傳送 %s / 接收 %s\r\nUSB 橋接丟棄／過濾計數：%d（不是 Moonlight 丟包率）\r\n流量取樣每 5 秒；尚未測量本輪最高頻寬或端到端延遲。\r\n\r\n檔案接收：%s\r\n接收入口：http://10.6.9.1:10690/upload\r\n已接收：%d 個檔案，共 %s；點「接收的檔案」查看。\r\n每個檔案會驗證 SHA256，不覆蓋既有檔案，不自動安裝或執行。\r\n\r\nMac 與 iPad 共用 Windows 10.6.9.1；Mac 10.6.9.2，iPad 10.6.9.3。Mac 可用 Moonlight 連接上方 Windows IP。", r.DeviceAuthorization, r.MacDHCPDiscoveries, r.MacDHCPOffers, r.MacDHCPACKs, proof, r.ObservedTransmitMbps, r.ObservedReceiveMbps, r.Traffic.PeakTransmitMbps, r.Traffic.PeakReceiveMbps, formatTransfer(r.Traffic.SentBytes), formatTransfer(r.Traffic.ReceivedBytes), r.MacBridgeDrops, files, r.FilesReceived, formatTransfer(r.FileBytes))
	if r.Status == "MONITOR_PAUSED" || r.Status == "MONITOR_WAITING" {
		detail = "目前未執行 USB 初始化。下方保留上一輪結果。\r\n\r\n" + detail
	}
	if r.Error != "" {
		detail = "停止原因：" + r.Error + "\r\n\r\n" + detail
	}
	if r.RuntimePreparationError != "" {
		detail += "\r\n元件準備詳情：" + r.RuntimePreparationError
	}
	if r.FileError != "" {
		detail += "\r\n檔案接收狀態：" + r.FileError
	}
	if r.MacPathMTUWarning != "" {
		if r.Status == "MAC_RUNNING" {
			title = "Mac USB 已連接 · 速度可能下降"
		}
		detail = "連線仍可使用，但封包大小設定未完整刷新，傳輸速度可能下降。重新連接 USB 後再試。\r\n\r\n" + detail
	}
	return
}

func connectionSubtitle(r ApplicationResult) string {
	kind := r.DeviceKind
	if kind == "" {
		return "等候 USB 裝置"
	}
	switch r.Status {
	case "WAITING_SHARED_HOST":
		return kind + " · 等候共享網卡"
	case "USB_RECOVERY_MAINTENANCE", "USB_RECOVERY_WAITING":
		return kind + " · USB 恢復維護"
	case "MONITOR_PAUSED":
		return kind + " · 連線已暫停"
	case "MONITOR_RETRYING":
		return kind + " · 正在自動恢復"
	case "MONITOR_WAITING":
		return "等候 USB 裝置"
	}
	if r.Status == "USB_APPLICATION_TRIAL_RUNNING" && (r.PeerIPv4NeighborVerified || r.HTTPVerified || r.SunshineClientTCPObserved) {
		return kind + " · USB 已連接"
	}
	if r.DHCPStarted || r.FileReceiverReady {
		return kind + " · USB 網路已啟動"
	}
	return kind + " · 已識別，正在準備"
}
