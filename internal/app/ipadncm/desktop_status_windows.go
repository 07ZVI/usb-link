//go:build windows && amd64

package ipadncm

import "suhang/usbnet/internal/contracts/desktopipc"

// The embedded device fields preserve older single-device renderer support.
// Detail overrides the selected device report with the combined diagnostics.
type desktopStatusSnapshot struct {
	DefaultNetworkIsolation any                        `json:"default_network_isolation,omitempty"`
	LocalUSBTrace           any                        `json:"local_usb_trace,omitempty"`
	PnPNativeTrace          any                        `json:"pnp_native_trace,omitempty"`
	NetworkOnly             networkOnlyIsolationStatus `json:"network_only"`
	DeveloperDebug          any                        `json:"developer_debug,omitempty"`
	ConnectionTiming        any                        `json:"connection_timing,omitempty"`
	PhotoIsolation          any                        `json:"photo_isolation,omitempty"`
	WPDTrace                any                        `json:"wpd_trace,omitempty"`
	PhotoPolicy             any                        `json:"photo_policy,omitempty"`
	NCMDirect               any                        `json:"ncm_direct,omitempty"`
	AMDSHold                any                        `json:"amds_hold,omitempty"`
	MacMTUCap               any                        `json:"mac_mtu_cap,omitempty"`
	ConnectionArchive       any                        `json:"connection_archive,omitempty"`
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
