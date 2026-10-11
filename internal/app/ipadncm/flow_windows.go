//go:build windows && amd64

package ipadncm

import (
	"suhang/usbnet/internal/transport/ipadsession"
	"sync"
	"time"
)

var flowCapture struct {
	sync.Mutex
	capture ipadsession.FlowCapture
}

func flowConnected(r ApplicationResult) bool {
	return (r.DeviceKind == "Mac" && r.FileReceiverReady || r.DeviceKind == "iPad" && r.DHCPStarted) && r.Status != "MONITOR_WAITING" && r.Status != "MONITOR_PAUSED" && r.Status != "WAITING_SHARED_HOST"
}
func FlowSnapshot() ipadsession.FlowResult {
	flowCapture.Lock()
	defer flowCapture.Unlock()
	return flowCapture.capture.Result
}
func flowStart(r ApplicationResult) {
	flowCapture.Lock()
	defer flowCapture.Unlock()
	if flowConnected(r) {
		flowCapture.capture.Start(time.Now(), r.Traffic, r.DeviceKind)
	}
}
func flowObserve(r ApplicationResult) ipadsession.FlowResult {
	flowCapture.Lock()
	defer flowCapture.Unlock()
	flowCapture.capture.Observe(time.Now(), r.Traffic, r.DeviceKind, flowConnected(r))
	return flowCapture.capture.Result
}
func flowCancel() {
	flowCapture.Lock()
	defer flowCapture.Unlock()
	flowCapture.capture.Cancel("使用者取消")
}

func flowReset() {
	flowCapture.Lock()
	defer flowCapture.Unlock()
	flowCapture.capture = ipadsession.FlowCapture{}
}
func FinishFlowSession() {
	flowCapture.Lock()
	defer flowCapture.Unlock()
	flowCapture.capture.Cancel("USB 連線已結束")
}
