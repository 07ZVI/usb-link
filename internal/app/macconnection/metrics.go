package macconnection

import (
	"regexp"
	"strconv"
	"strings"
	"suhang/usbnet/internal/diagnostics/throughput"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/ipadsession"
	"suhang/usbnet/internal/transport/ncm"
)

type Result struct {
	FirewallAnchorProjection   *netconfig.MacAnchorProjection        `json:"firewall_anchor_projection,omitempty"`
	FirewallNullProjection     *netconfig.MacNullProjection          `json:"firewall_null_projection,omitempty"`
	BridgeProcessPID           uint32                                `json:"bridge_process_pid,omitempty"`
	BridgeProcessCreation      uint64                                `json:"bridge_process_creation_filetime,omitempty,string"`
	BridgeProcessBound         bool                                  `json:"bridge_process_binding_observed"`
	BridgeNetworkScriptTimings []netconfig.BridgeNetworkScriptTiming `json:"bridge_network_script_timings,omitempty"`
	NativeDiagnosticSource     string                                `json:"native_diagnostic_source,omitempty"`
	NativeStartupFailure       netconfig.NativeStepDiagnostic        `json:"native_startup_failure,omitempty"`
	InterfaceConfig            []interfaceconfig.OperationTiming     `json:"mac_interface_configuration_operations,omitempty"`
	NCMDescriptors             string                                `json:"mac_ncm_descriptor_summary,omitempty"`
	EffectiveMTU               int                                   `json:"effective_mtu,omitempty"`
	PathMTUWarning             string                                `json:"path_mtu_warning,omitempty"`
	PreparationError           string                                `json:"runtime_preparation_error,omitempty"`
	BenchmarkURL               string                                `json:"benchmark_url,omitempty"`
	Benchmark                  throughput.Report                     `json:"throughput_test"`
	ShareReady                 bool                                  `json:"share_ready"`
	ShareError                 string                                `json:"share_error,omitempty"`
	DHCPStarted                bool                                  `json:"mac_usb_dhcp_started"`
	DHCPDiscoveries            uint64                                `json:"mac_dhcp_discoveries"`
	DHCPOffers                 uint64                                `json:"mac_dhcp_offers"`
	DHCPACKs                   uint64                                `json:"mac_dhcp_acks_not_address_application_proof"`
	SunshineTCPObserved        bool                                  `json:"mac_to_sunshine_established_usb_ipv4_tcp_observed"`
	TCPQueryError              string                                `json:"tcp_query_error,omitempty"`
	BridgeFailureClass         string                                `json:"bridge_failure_class,omitempty"`
	Stage                      string                                `json:"stage"`
	BridgeStarted              bool                                  `json:"bridge_started"`
	Ready                      bool                                  `json:"bridge_initialized_not_peer_proof"`
	PeerResolved               bool                                  `json:"mac_arp_peer_resolved"`
	HeldSeconds                int64                                 `json:"held_seconds"`
	Traffic                    ipadsession.Traffic                   `json:"traffic"`
	BridgeDrops                uint64                                `json:"bridge_drops_including_filtered_packets_not_moonlight_loss"`
	LegacyServiceMigrated      bool                                  `json:"owned_legacy_service_suspended"`
	CleanupConfirmed           bool                                  `json:"owned_network_cleanup_confirmed"`
	ServicesReady              bool                                  `json:"services_ready"`
	ServicesError              string                                `json:"services_error,omitempty"`
	Error                      string                                `json:"error,omitempty"`
}

func parsePathState(line string) (mtu int, healthy, ok bool) {
	const marker = "USB_MAC_PATH_STATE "
	if len(line) > 4096 {
		return
	}
	i := strings.Index(line, marker)
	if i < 0 {
		return
	}
	fields := strings.Fields(line[i+len(marker):])
	if len(fields) != 2 || !strings.HasPrefix(fields[0], "mtu=") || !strings.HasPrefix(fields[1], "healthy=") {
		return
	}
	n, err := strconv.Atoi(strings.TrimPrefix(fields[0], "mtu="))
	if err != nil || (n != 1500 && n != 9000 && n != 16000) {
		return
	}
	v := strings.TrimPrefix(fields[1], "healthy=")
	if v != "true" && v != "false" {
		return
	}
	return n, v == "true", true
}

var descriptorSummaryPattern = regexp.MustCompile(`^[A-Za-z0-9 _{}()\[\],:=./-]+$`)

// parseDescriptorSummary accepts only the bridge's fixed numeric one-line
// summary. It is display text for the exported diagnostics, never an input to
// any connection decision.
func parseDescriptorSummary(line string) (string, bool) {
	if len(line) > 4096 {
		return "", false
	}
	i := strings.Index(line, ncm.DescriptorSummaryPrefix)
	if i < 0 {
		return "", false
	}
	summary := strings.TrimSpace(line[i+len(ncm.DescriptorSummaryPrefix):])
	if summary == "" || len(summary) > 2048 || !descriptorSummaryPattern.MatchString(summary) {
		return "", false
	}
	return summary, true
}

var counterPattern = regexp.MustCompile(`\b(ToMacBytes|ToWindowsBytes|Dropped):([0-9]+)\b`)

func parseCounters(line string) (in, out, drops uint64, ok bool) {
	if len(line) > 4096 {
		return
	}
	v := map[string]uint64{}
	for _, m := range counterPattern.FindAllStringSubmatch(line, -1) {
		n, e := strconv.ParseUint(m[2], 10, 64)
		if e != nil {
			return 0, 0, 0, false
		}
		if _, exists := v[m[1]]; exists {
			return 0, 0, 0, false
		}
		v[m[1]] = n
	}
	if len(v) != 3 {
		return 0, 0, 0, false
	}
	return v["ToWindowsBytes"], v["ToMacBytes"], v["Dropped"], true
}

func bridgeFailureClass(line string) string {
	for _, p := range []struct{ needle, code string }{{"existing subnet", "SUBNET_CONFLICT"}, {"subnet already used", "SUBNET_CONFLICT"}, {"peer not resolved", "PEER_UNRESOLVED"}, {"Duplicate", "DUPLICATE_ADDRESS"}, {"Wintun", "WINTUN_FAILURE"}, {"WinUSB", "WINUSB_FAILURE"}, {"PowerShell", "NETWORK_CONFIGURATION_FAILURE"}, {"powershell", "NETWORK_CONFIGURATION_FAILURE"}, {"control", "USB_CONTROL_FAILURE"}, {"read", "USB_READ_FAILURE"}, {"write", "USB_WRITE_FAILURE"}} {
		if strings.Contains(line, p.needle) {
			return p.code
		}
	}
	return "BRIDGE_ERROR_OTHER"
}
