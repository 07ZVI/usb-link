//go:build windows && amd64

package ipadncm

import "suhang/usbnet/internal/contracts/desktopipc"

// The embedded device fields preserve older single-device renderer support.
// Detail overrides the selected device report with the combined diagnostics.
type desktopStatusSnapshot struct {
	DeveloperDebug   any `json:"developer_debug,omitempty"`
	ConnectionTiming any `json:"connection_timing,omitempty"`
	PhotoIsolation   any `json:"photo_isolation,omitempty"`
	desktopipc.DeviceStatus
	Event             string                      `json:"event"`
	Connections       string                      `json:"connections"`
	Version           string                      `json:"version"`
	Stopping          bool                        `json:"stopping"`
	ShareURL          string                      `json:"share_url"`
	NativeSMB         bool                        `json:"native_smb"`
	NativeAccount     string                      `json:"native_account"`
	ShareProblem      string                      `json:"share_problem"`
	ShareReady        bool                        `json:"share_ready"`
	ShareEnabled      bool                        `json:"share_enabled"`
	Notice            string                      `json:"notice"`
	Startup           bool                        `json:"startup"`
	StartupBusy       bool                        `json:"startup_busy"`
	StartupRequested  bool                        `json:"startup_requested"`
	StartupRequestID  string                      `json:"startup_request_id"`
	StartupRejectedID string                      `json:"startup_rejected_id"`
	Independent       bool                        `json:"independent"`
	IPadNetworkPolicy SimplifiedIPadNetworkStatus `json:"ipad_network_policy"`
	Devices           []desktopipc.DeviceStatus   `json:"devices"`
	Detail            string                      `json:"detail"`
}
