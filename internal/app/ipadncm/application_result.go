package ipadncm

import (
	"suhang/usbnet/internal/transport/ipadsession"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/diagnostics/throughput"
	"sync"
)

type ApplicationRecovery struct {
	PersistentAddressPreserved bool   `json:"verified_persistent_ipv4_address_preserved"`
	Pending                    bool   `json:"pending_application_session_found"`
	FirewallRemoved            bool   `json:"owned_firewall_rules_removed"`
	ResidentFirewallPreserved  bool   `json:"resident_firewall_rules_preserved_for_reuse,omitempty"`
	AddressRemoved             bool   `json:"temporary_ipv4_address_removed_or_adapter_absent"`
	JournalCleared             bool   `json:"application_journal_cleared"`
	Error                      string `json:"error,omitempty"`
}
type ApplicationResult struct {
	MacFirewallAnchorProjection                    *netconfig.MacAnchorProjection        `json:"mac_firewall_anchor_projection,omitempty"`
	MacFirewallNullProjection                      *netconfig.MacNullProjection          `json:"mac_firewall_null_projection,omitempty"`
	MacBridgeNetworkScriptTimings                  []netconfig.BridgeNetworkScriptTiming `json:"mac_bridge_network_script_timings,omitempty"`
	MacBridgeProcessPID                            uint32                                `json:"mac_bridge_process_pid,omitempty"`
	MacBridgeProcessCreation                       uint64                                `json:"mac_bridge_process_creation_filetime,omitempty,string"`
	MacBridgeProcessBound                          bool                                  `json:"mac_bridge_process_binding_observed"`
	RuntimePreparationError                        string                                `json:"runtime_preparation_error,omitempty"`
	AutoRetryAttempt                               int                                   `json:"automatic_retry_attempt,omitempty"`
	AutoRetrySeconds                               int                                   `json:"automatic_retry_seconds,omitempty"`
	BenchmarkURL                                   string                                `json:"benchmark_url,omitempty"`
	Benchmark                                      throughput.Report                     `json:"throughput_test"`
	DesktopError                                   string                                `json:"desktop_error,omitempty"`
	ShareReady                                     bool                                  `json:"share_ready"`
	ShareError                                     string                                `json:"share_error,omitempty"`
	MacDHCPStarted                                 bool                                  `json:"mac_dhcp_started"`
	MacDHCPDiscoveries, MacDHCPOffers, MacDHCPACKs uint64
	MacSunshineTCPObserved                         bool                    `json:"mac_sunshine_usb_tcp_observed"`
	DeviceKind                                     string                  `json:"device_kind,omitempty"`
	MacPeerResolved                                bool                    `json:"mac_arp_peer_resolved"`
	MacEffectiveMTU                                int                     `json:"mac_effective_mtu,omitempty"`
	MacPathMTUWarning                              string                  `json:"mac_path_mtu_warning,omitempty"`
	FileReceiverReady                              bool                    `json:"file_receiver_ready"`
	FilesReceived                                  uint64                  `json:"files_received"`
	FileBytes                                      uint64                  `json:"file_bytes_received"`
	FileError                                      string                  `json:"file_error,omitempty"`
	MacBridgeDrops                                 uint64                  `json:"mac_bridge_drops_including_filtered_not_moonlight_loss"`
	Performance                                    ipadsession.Performance `json:"performance"`
	MTU                                            uint32                  `json:"usb_interface_mtu"`
	ActiveChecksCacheOnly                          bool                    `json:"active_checks_cached_pnp_no_usb_descriptors"`

	DeviceAuthorization       string              `json:"device_authorization_mode,omitempty"`
	PairedTLSAuthenticated    bool                `json:"paired_tls_authenticated_at_consent"`
	EchoSamples               uint32              `json:"verified_unicast_echo_samples"`
	EchoMinMilliseconds       uint32              `json:"echo_min_integer_ms_not_stream_latency"`
	EchoMaxMilliseconds       uint32              `json:"echo_max_integer_ms_not_stream_latency"`
	Traffic                   ipadsession.Traffic `json:"traffic"`
	USBSpeed                  string              `json:"usb_operating_speed_class,omitempty"`
	USBSpeedError             string              `json:"usb_speed_error,omitempty"`
	ReportedTransmitBPS       uint64              `json:"driver_reported_transmit_bps,omitempty"`
	ReportedReceiveBPS        uint64              `json:"driver_reported_receive_bps,omitempty"`
	TCPQueryError             string              `json:"tcp_query_error,omitempty"`
	TCPAddressFamily          string              `json:"sunshine_observed_usb_address_family,omitempty"`
	PeerIPv4NeighborVerified  bool                `json:"peer_ipv4_neighbor_mac_verified"`
	RouterAdvertised          bool                `json:"dhcp_router_advertised_local_only"`
	Status                    string              `json:"status"`
	Consent                   bool                `json:"application_trial_consent"`
	WindowsIPv4               string              `json:"windows_usb_ipv4,omitempty"`
	ProposedIPadIPv4          string              `json:"dhcp_single_peer_ipv4,omitempty"`
	WindowsIPv6               string              `json:"windows_usb_ipv6,omitempty"`
	DHCPStarted               bool                `json:"dhcp_socket_started"`
	DHCPDiscoveries           uint32              `json:"dhcp_discover_count"`
	DHCPOffers                uint32              `json:"dhcp_offers_sent"`
	DHCPACKs                  uint32              `json:"dhcp_acks_sent_not_address_application_proof"`
	DHCPDeclined              bool                `json:"peer_declined_address"`
	DHCPError                 string              `json:"dhcp_error,omitempty"`
	HTTPVerified              bool                `json:"ipad_ipv4_http_nonce_ack_verified"`
	SunshineLoopbackHTTP      bool                `json:"sunshine_loopback_serverinfo_valid"`
	SunshineUSBLocalHTTP      bool                `json:"sunshine_usb_local_serverinfo_valid_not_ipad_proof"`
	SunshineClientTCPObserved bool                `json:"ipad_to_sunshine_established_tcp_observed"`
	MDNSRegistered            bool                `json:"native_usb_scoped_mdns_registered_not_client_discovery_proof"`
	MDNSError                 string              `json:"mdns_error,omitempty"`
	MDNSCleanupError          string              `json:"mdns_cleanup_error,omitempty"`
	WindowOpened              bool                `json:"native_status_window_opened"`
	UserReportsStream         bool                `json:"user_reported_stream_normal_not_independent_proof"`
	ElapsedSeconds            int64               `json:"held_connection_seconds"`
	RemainingSeconds          int64               `json:"remaining_test_seconds"`
	ObservedReceiveMbps       float64             `json:"usb_counter_receive_mbps_not_bandwidth_limit"`
	ObservedTransmitMbps      float64             `json:"usb_counter_transmit_mbps_not_bandwidth_limit"`
	NetworkVerified           bool                `json:"network_verified"`
	MoonlightVerified         bool                `json:"moonlight_verified"`
	Recovery                  ApplicationRecovery `json:"application_cleanup"`
	Error                     string              `json:"error,omitempty"`
}
type applicationState struct {
	sync.Mutex
	r         ApplicationResult
	Settings  func()
	Router    bool
	Minimized bool
	selected  func() *applicationState
}

func (s *applicationState) update(f func(*ApplicationResult)) {
	if s.selected != nil {
		if target := s.selected(); target != nil && target != s {
			target.update(f)
			return
		}
	}
	s.Lock()
	f(&s.r)
	observed := s.r
	s.Unlock()
	observeStartupReadiness(observed)
	autoSelectSession(s)
}
func (s *applicationState) snapshot() ApplicationResult {
	if s.selected != nil {
		if target := s.selected(); target != nil && target != s {
			return target.snapshot()
		}
	}
	s.Lock()
	defer s.Unlock()
	r := s.r
	r.Performance = r.Performance.Snapshot()
	r.MacBridgeNetworkScriptTimings = netconfig.CopyBridgeNetworkScriptTimings(r.MacBridgeNetworkScriptTimings)
	r.MacFirewallNullProjection = netconfig.CopyMacNullProjection(r.MacFirewallNullProjection)
	r.MacFirewallAnchorProjection = netconfig.CopyMacAnchorProjection(r.MacFirewallAnchorProjection)
	return r
}

// Only locally produced actual child binding scalars enter this report. They
// identify a historical measurement sample, never authorize process control or
// contribute to network readiness. A new unbound result clears the old sample.
func applyMacBridgeDiagnostics(r *ApplicationResult, m macconnection.Result) {
	r.MacBridgeProcessBound = m.BridgeProcessBound && m.BridgeProcessPID != 0 && m.BridgeProcessCreation != 0
	r.MacBridgeProcessPID, r.MacBridgeProcessCreation = 0, 0
	r.MacBridgeNetworkScriptTimings = nil
	r.MacFirewallNullProjection = nil
	r.MacFirewallAnchorProjection = nil
	if r.MacBridgeProcessBound {
		r.MacBridgeProcessPID, r.MacBridgeProcessCreation = m.BridgeProcessPID, m.BridgeProcessCreation
		r.MacBridgeNetworkScriptTimings = netconfig.CopyBridgeNetworkScriptTimings(m.BridgeNetworkScriptTimings)
		r.MacFirewallNullProjection = netconfig.CopyMacNullProjection(m.FirewallNullProjection)
		r.MacFirewallAnchorProjection = netconfig.CopyMacAnchorProjection(m.FirewallAnchorProjection)
	}
}
