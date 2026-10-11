//go:build windows && amd64

package ipadncm

import (
	"context"
	"strconv"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/sharing/fileshare"
	"suhang/usbnet/internal/app/usbhost"
	"time"
)

var remoteInfo func() (string, string)
var remoteEnabled func() bool
var remoteEnable func(bool) error
var remoteAutoUpgrade func() bool
var remoteSetAutoUpgrade func(bool) error

func SetAutomaticUSBUpdates(set func(bool) error, get func() bool) {
	remoteSetAutoUpgrade, remoteAutoUpgrade = set, get
}

func SetRemoteMaintenance(info func() (string, string), enable func(bool) error, enabled func() bool) {
	remoteInfo = info
	remoteEnable = enable
	remoteEnabled = enabled
}
func MaintenanceReady() bool {
	s := deviceMonitor("Mac")
	if s == nil {
		return false
	}
	r := s.snapshot()
	return r.DeviceKind == "Mac" && r.FileReceiverReady && r.Status != "MONITOR_WAITING" && r.Status != "MONITOR_PAUSED" && r.Status != "WAITING_SHARED_HOST"
}

func ConnectionRuntimeDetails() any {
	out := map[string]any{}
	for _, kind := range []string{"Mac", "iPad"} {
		if state := deviceMonitor(kind); state != nil {
			r := state.snapshot()
			title, _, _ := applicationView(r, false)
			details := map[string]any{"status": r.Status, "error": r.Error, "usb_speed": r.USBSpeed, "usb_speed_error": r.USBSpeedError, "windows_ipv4": r.WindowsIPv4, "throughput": r.Benchmark, "dhcp_started": r.DHCPStarted || r.MacDHCPStarted, "shared_host": usbhost.Details(),
				"peer_ipv4": r.ProposedIPadIPv4, "peer_neighbor_verified": r.PeerIPv4NeighborVerified, "dhcp_acks": r.DHCPACKs, "file_ready": r.FileReceiverReady, "share_ready": r.ShareReady, "native_smb": connectioninstall.NativeSMBDiagnostics(), "smb": fileshare.SMBDiagnostics(map[string]string{"Mac": "10.6.9.2", "iPad": "10.6.9.3"}[kind]), "dhcp_error": r.DHCPError, "http_verified": r.HTTPVerified, "sunshine_usb_local_http": r.SunshineUSBLocalHTTP,
				"connection_title": title, "connection_subtitle": connectionSubtitle(r), "sunshine_client_tcp_observed": r.SunshineClientTCPObserved, "sunshine_tcp_family": r.TCPAddressFamily}
			if kind == "Mac" {
				details["bridge_network_script_timings"] = r.MacBridgeNetworkScriptTimings
				details["firewall_null_projection"] = r.MacFirewallNullProjection
				details["firewall_anchor_projection"] = r.MacFirewallAnchorProjection
				details["bridge_process_binding_observed"] = r.MacBridgeProcessBound
				details["bridge_process_pid"] = r.MacBridgeProcessPID
				details["bridge_process_creation_filetime"] = strconv.FormatUint(r.MacBridgeProcessCreation, 10)
				details["effective_mtu"] = r.MacEffectiveMTU
				details["path_mtu_warning"] = r.MacPathMTUWarning
				details["peer_ipv4"] = "10.6.9.2"
				details["peer_neighbor_verified"] = r.MacPeerResolved
				details["dhcp_acks"] = r.MacDHCPACKs
			}
			if kind == "iPad" {
				details["network_debug"] = ipadNetDebug.export()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				ids, complete := idlePnPIDs(ctx)
				cancel()
				_, presence := idleUSBPresenceFromIDs(onlyIPadIDs(ids), complete)
				products := []string{}
				rootCount := 0
				for _, id := range onlyIPadIDs(ids) {
					parts := strings.SplitN(strings.ToUpper(id), `\`, 3)
					if len(parts) == 3 && !strings.Contains(parts[1], "&MI_") {
						rootCount++
						if len(products) < 4 {
							product := strings.Split(parts[1], "&")
							if len(product) >= 2 {
								products = append(products, product[1])
							}
						}
					}
				}
				details["cached_usb_presence"] = map[string]any{"readable": presence.readable, "absent": presence.absent, "supported_candidate": presence.candidate, "apple_mobile_roots": rootCount, "product_ids": products}
				details["monitor"] = ConnectionMonitorDiagnostics()
			}
			out[kind] = details
		}
	}
	return out
}
