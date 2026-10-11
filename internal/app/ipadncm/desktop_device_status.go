package ipadncm

import (
	"fmt"
	"suhang/usbnet/internal/diagnostics/throughput"
)

// Each slot derives its metrics and measurement state from its own USB session.
func desktopDeviceStatus(r ApplicationResult, stopping bool) map[string]any {
	speedServer := throughput.DeviceCurrent(r.DeviceKind)
	nativeReady, nativeBusy, nativeProgress := speedServer.NativeState()
	nativeReport := speedServer.NativeReport()
	measurement := nativeReport.Summary()
	if r.DeviceKind == "iPad" {
		measurement = "在 iPad 瀏覽器開啟測速網址。"
	} else if nativeReport.Status == "" {
		if nativeReady {
			measurement = "Mac 測速端已就緒，按「開始測速」測試雙向吞吐。"
		} else {
			measurement = "Mac 測試程式尚未啟動，暫時無法測速；不影響 USB 連線或串流。"
		}
	}
	measuring, progress := nativeBusy, nativeProgress
	latencyText := "延遲 · 未測得"
	if ms, ok := speedServer.LiveLatency(); ok {
		latencyText = fmt.Sprintf("HTTP 往返 · %.1f ms", ms)
	} else if r.EchoSamples > 0 && r.Status == "USB_APPLICATION_TRIAL_RUNNING" {
		latencyText = fmt.Sprintf("啟動時 ICMP 往返 · %d–%d ms", r.EchoMinMilliseconds, r.EchoMaxMilliseconds)
	} else if r.Benchmark.IdleRTT.RTTSamples > 0 {
		latencyText = fmt.Sprintf("上次測速 HTTP 往返 · %.1f ms", r.Benchmark.IdleRTT.RTTMedianMS)
	}
	title, _, detail := applicationView(r, stopping)
	speed := "USB 協商速率：" + r.USBSpeed
	if r.USBSpeed == "" {
		speed = "USB 協商速率尚未取得；即時流量不代表頻寬上限。"
	}
	health := "尚未取得本輪介面錯誤統計。"
	if r.DeviceKind == "iPad" && r.Performance.Samples > 0 {
		f := r.Performance.Faults
		health = fmt.Sprintf("本輪介面：傳送丟棄 %d / 接收丟棄 %d / 錯誤 %d；不代表 Moonlight 客戶端丟包率。", f.OutDiscards, f.InDiscards, f.OutErrors+f.InErrors)
	}
	if r.DeviceKind == "Mac" {
		health = "橋接過濾計數不代表串流丟包；客戶端丟包率尚未直接取得。"
		if r.MacPathMTUWarning != "" {
			health = "封包大小設定未完整刷新，速度可能下降；重新連接 USB 後再試。"
		}
	}
	peer, addressState := desktopPeerAddress(r, stopping)
	return map[string]any{
		"device": r.DeviceKind, "connection_state": desktopConnectionState(r, stopping), "title": title, "subtitle": connectionSubtitle(r),
		"detail": detail, "windows_ipv4": r.WindowsIPv4, "connected": sessionRunning(r),
		"peer_ipv4": peer, "peer_address_state": addressState, "retry_available": !stopping && desktopRetryAvailable(r),
		"tx": r.ObservedTransmitMbps, "rx": r.ObservedReceiveMbps, "speed": speed, "health": health,
		"latency": latencyText, "benchmark_url": r.BenchmarkURL, "benchmark_summary": measurement,
		"benchmark_ready":     nativeReady,
		"benchmark_available": r.DeviceKind == "Mac" && r.ServicesReady && r.Status == "MAC_RUNNING",
		"measurement_busy":    measuring, "measurement_progress": progress,
		"benchmark_visible": r.DeviceKind != "iPad",
	}
}

// DHCP acknowledgement describes allocation, while observed peer traffic
// confirms application. Waiting/paused snapshots can retain an older session.
func desktopPeerAddress(r ApplicationResult, stopping bool) (string, string) {
	if stopping || !sessionRunning(r) {
		return "", "尚未分配"
	}
	switch r.DeviceKind {
	case "Mac":
		if r.MacPeerResolved || r.MacSunshineTCPObserved {
			return "10.6.9.2", "已確認"
		}
		if r.MacDHCPACKs > 0 {
			return "10.6.9.2", "待確認"
		}
	case "iPad":
		if r.ProposedIPadIPv4 != "" && !r.DHCPDeclined {
			if r.PeerIPv4NeighborVerified || r.HTTPVerified || r.SunshineClientTCPObserved {
				return r.ProposedIPadIPv4, "已確認"
			}
			if r.DHCPACKs > 0 {
				return r.ProposedIPadIPv4, "待確認"
			}
		}
	}
	return "", "尚未分配"
}

func desktopRetryAvailable(r ApplicationResult) bool {
	return r.Status == "MONITOR_PAUSED" || r.Status == "MONITOR_RETRYING"
}

// A card retry never changes the selected session or restarts the other device.
func desktopRetryDevices(results []ApplicationResult, kind string, request func(string)) bool {
	retried := false
	for _, r := range results {
		if (kind != "" && r.DeviceKind != kind) || !desktopRetryAvailable(r) {
			continue
		}
		if r.DeviceKind != "Mac" && r.DeviceKind != "iPad" {
			continue
		}
		request(r.DeviceKind)
		retried = true
	}
	return retried
}

// A running host transport is still connecting until its peer is observed.
// Waiting snapshots can retain old errors and must still display as offline.
func desktopConnectionState(r ApplicationResult, stopping bool) string {
	if stopping || r.Status == "MONITOR_WAITING" || r.Status == "APPLICATION_TRIAL_ENDED_RESTORING" {
		return "offline"
	}
	if r.Status == "USB_RECOVERY_MAINTENANCE" || r.Status == "USB_RECOVERY_WAITING" {
		return "error"
	}
	if r.Status == "MONITOR_RETRYING" || r.Status == "WAITING_SHARED_HOST" || r.Error == "APPLICATION_SHARED_HOST_UNAVAILABLE" {
		return "connecting"
	}
	if r.Status == "MONITOR_PAUSED" || r.Error != "" {
		return "error"
	}
	if sessionRunning(r) {
		if r.DeviceKind == "Mac" && (r.MacPeerResolved || r.MacSunshineTCPObserved) || r.DeviceKind == "iPad" && (r.PeerIPv4NeighborVerified || r.HTTPVerified || r.SunshineClientTCPObserved) {
			return "connected"
		}
	}
	return "connecting"
}
