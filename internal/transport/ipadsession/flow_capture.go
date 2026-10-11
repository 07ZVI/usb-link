package ipadsession

import (
	"fmt"
	"time"
)

// FlowCapture observes existing traffic only. It does not generate test traffic
// and its averages must never be labelled as the maximum link bandwidth.
type FlowResult struct {
	Status                    string  `json:"status"`
	Seconds                   float64 `json:"seconds"`
	TransmitMbps, ReceiveMbps float64
	SentBytes, ReceivedBytes  uint64
	Error                     string `json:"error,omitempty"`
}

func (r FlowResult) Summary() string {
	switch r.Status {
	case "waiting":
		return "等待下一筆流量樣本…請正常串流或傳輸檔案。"
	case "sampling":
		return fmt.Sprintf("流量統計 %d / 30 秒 · 傳送 %.1f / 接收 %.1f Mbps", int(r.Seconds), r.TransmitMbps, r.ReceiveMbps)
	case "idle":
		return fmt.Sprintf("%.1f 秒內未觀察到資料傳輸；沒有取得有效速率。\n請在串流或傳檔時記錄；測頻寬請使用主動測速。", r.Seconds)
	case "complete":
		return fmt.Sprintf("流量統計完成 · 平均傳送 %.3f / 接收 %.3f Mbps（%.1f 秒）\n這是現有流量，不是線路最高頻寬。", r.TransmitMbps, r.ReceiveMbps, r.Seconds)
	case "failed":
		return "流量統計未完成：" + r.Error
	default:
		return "可直接統計 30 秒串流流量；主動測速需原生對端。"
	}
}

type FlowCapture struct {
	Result             FlowResult
	started, requested time.Time
	base               Traffic
	lastSamples        uint64
	device             string
}

func (c *FlowCapture) Start(now time.Time, t Traffic, device string) {
	*c = FlowCapture{Result: FlowResult{Status: "waiting"}, requested: now, base: t, lastSamples: t.Samples, device: device}
}
func (c *FlowCapture) Cancel(reason string) {
	if c.Result.Status == "waiting" || c.Result.Status == "sampling" {
		c.Result.Status = "failed"
		c.Result.Error = reason
	}
}
func (c *FlowCapture) Observe(now time.Time, t Traffic, device string, connected bool) {
	if c.Result.Status != "waiting" && c.Result.Status != "sampling" {
		return
	}
	if !connected || device != c.device {
		c.Cancel("USB 連線已結束或裝置已變更")
		return
	}
	if now.Sub(c.requested) > 50*time.Second {
		c.Cancel("流量取樣逾時")
		return
	}
	if t.Samples < c.lastSamples || t.CounterResets != c.base.CounterResets || t.SentBytes < c.base.SentBytes || t.ReceivedBytes < c.base.ReceivedBytes {
		c.Cancel("介面計數器已重置")
		return
	}
	if t.Samples == c.lastSamples {
		return
	}
	c.lastSamples = t.Samples
	if c.Result.Status == "waiting" {
		c.base = t
		c.started = now
		c.Result.Status = "sampling"
		return
	}
	sec := now.Sub(c.started).Seconds()
	if sec <= 0 {
		return
	}
	c.Result.Seconds = sec
	c.Result.SentBytes = t.SentBytes - c.base.SentBytes
	c.Result.ReceivedBytes = t.ReceivedBytes - c.base.ReceivedBytes
	c.Result.TransmitMbps = float64(c.Result.SentBytes) * 8 / sec / 1e6
	c.Result.ReceiveMbps = float64(c.Result.ReceivedBytes) * 8 / sec / 1e6
	if sec >= 30 {
		c.Result.Status = "complete"
		if c.Result.SentBytes == 0 && c.Result.ReceivedBytes == 0 {
			c.Result.Status = "idle"
		}
	}
}
