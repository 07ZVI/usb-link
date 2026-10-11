//go:build windows && amd64

package connectioninstall

import (
	"sync"
	"time"
)

type smbUIReceipt struct {
	RequestID            string    `json:"request_id"`
	Action               string    `json:"action"`
	CoreReceived         time.Time `json:"core_received_utc"`
	ReplyReady           time.Time `json:"reply_ready_utc"`
	RendererAcknowledged time.Time `json:"renderer_acknowledged_utc"`
}

var smbUIReceipts struct {
	sync.Mutex
	rows []smbUIReceipt
}

func RecordSMBUIResult(id, action, stage string) {
	if len(id) != 32 {
		return
	}
	smbUIReceipts.Lock()
	defer smbUIReceipts.Unlock()
	i := -1
	for n, r := range smbUIReceipts.rows {
		if r.RequestID == id {
			i = n
			break
		}
	}
	if i < 0 {
		if len(smbUIReceipts.rows) >= 16 {
			smbUIReceipts.rows = smbUIReceipts.rows[1:]
		}
		smbUIReceipts.rows = append(smbUIReceipts.rows, smbUIReceipt{RequestID: id})
		i = len(smbUIReceipts.rows) - 1
	}
	r := &smbUIReceipts.rows[i]
	if action != "" {
		r.Action = action
	}
	switch stage {
	case "core-received":
		r.CoreReceived = time.Now()
	case "reply-ready":
		r.ReplyReady = time.Now()
	case "renderer-acknowledged":
		r.RendererAcknowledged = time.Now()
	}
}
func nativeSMBUIResultDiagnostics() []smbUIReceipt {
	smbUIReceipts.Lock()
	defer smbUIReceipts.Unlock()
	return append([]smbUIReceipt(nil), smbUIReceipts.rows...)
}
