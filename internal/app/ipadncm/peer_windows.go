//go:build windows && amd64

package ipadncm

import (
	"context"
	"crypto/rand"
	"golang.org/x/sys/windows"
	"net"
	"runtime"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"time"
	"unsafe"
)

type Neighbor struct {
	IP                 string `json:"ip"`
	State              uint32 `json:"neighbor_state"`
	LinkAddressPresent bool   `json:"link_address_present"`
	IsRouter           bool   `json:"is_router"`
	Unreachable        bool   `json:"unreachable"`
}
type EchoAttempt struct {
	TargetStableAfter    bool    `json:"target_identity_source_and_scope_rechecked_after_reply"`
	Destination          string  `json:"destination"`
	InterfaceIndex       uint32  `json:"ipv6_scope_interface_index"`
	APIReplies           uint32  `json:"api_reply_count"`
	APIParsed            bool    `json:"native_reply_parser_accepted"`
	ReplyStatus          *uint32 `json:"reply_status,omitempty"`
	ReplyIP              string  `json:"reply_ip,omitempty"`
	ReplyScopeLE         uint32  `json:"reply_scope_le"`
	ReplyScopeBE         uint32  `json:"reply_scope_be"`
	ReplyScopeReported   bool    `json:"reply_scope_reported"`
	NoncePayloadMatches  bool    `json:"echo_nonce_payload_matches"`
	EchoReplyVerified    bool    `json:"echo_reply_content_verified_not_interface_proof"`
	ScopedNonceRoundtrip bool    `json:"same_scope_nonlocal_nonce_echo_verified"`
	RTTMilliseconds      uint32  `json:"echo_roundtrip_ms_not_stream_latency"`
	Error                string  `json:"error,omitempty"`
}
type PeerProbe struct {
	adapterKey        string
	sourceIPv6        string
	ipv6Scope         uint32
	Status            string        `json:"status"`
	Consent           bool          `json:"consent_in_trial_dialog"`
	InterfaceIndex    uint32        `json:"target_interface_index,omitempty"`
	NeighborsBefore   []Neighbor    `json:"target_neighbors_before,omitempty"`
	NeighborsAfter    []Neighbor    `json:"target_neighbors_after,omitempty"`
	NeighborError     string        `json:"neighbor_query_error,omitempty"`
	Echoes            []EchoAttempt `json:"ipv6_echo_attempts,omitempty"`
	IPv6EchoVerified  bool          `json:"scoped_unicast_ipv6_echo_verified"`
	NetworkVerified   bool          `json:"network_verified"`
	MoonlightVerified bool          `json:"moonlight_verified"`
}

// Win64 SDK ABI: SOCKADDR_INET28, index4, LUID8, physical32, len4,
// state4, flags1+padding3, reachability4. Table rows align to8.
type ipNetRow2 struct {
	Address        windows.RawSockaddrInet6
	Index          uint32
	Luid           uint64
	Physical       [32]byte
	PhysicalLength uint32
	State          uint32
	Flags          uint8
	_              [3]byte
	Reachability   uint32
}
type ipNetTable2 struct {
	Count uint32
	_     uint32
	Rows  [1]ipNetRow2
}

var _ [88 - int(unsafe.Sizeof(ipNetRow2{}))]byte
var _ [int(unsafe.Sizeof(ipNetRow2{})) - 88]byte
var _ [8 - int(unsafe.Offsetof(ipNetTable2{}.Rows))]byte
var _ [int(unsafe.Offsetof(ipNetTable2{}.Rows)) - 8]byte

func targetNeighbors(a NetworkAdapter) ([]Neighbor, string) {
	dll := windows.NewLazySystemDLL("iphlpapi.dll")
	get := dll.NewProc("GetIpNetTable2")
	free := dll.NewProc("FreeMibTable")
	if get.Find() != nil || free.Find() != nil {
		return nil, "NEIGHBOR_API_UNAVAILABLE"
	}
	var table *ipNetTable2
	rc, _, _ := get.Call(windows.AF_UNSPEC, uintptr(unsafe.Pointer(&table)))
	if rc == uintptr(windows.ERROR_NOT_FOUND) {
		return nil, ""
	}
	if rc != 0 {
		return nil, "NEIGHBOR_QUERY_" + eno(windows.Errno(rc))
	}
	if table == nil {
		return nil, "NEIGHBOR_TABLE_MISSING"
	}
	defer free.Call(uintptr(unsafe.Pointer(table)))
	if table.Count > 4096 {
		return nil, "NEIGHBOR_TABLE_LIMIT"
	}
	var out []Neighbor
	for _, row := range unsafe.Slice(&table.Rows[0], int(table.Count)) {
		if row.Index != a.InterfaceIndex || row.Luid != a.luid {
			continue
		}
		if row.PhysicalLength > 32 || row.State > 6 {
			return out, "TARGET_NEIGHBOR_ENTRY_INVALID"
		}
		var ip net.IP
		switch row.Address.Family {
		case windows.AF_INET:
			v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
			ip = net.IP(v.Addr[:])
		case windows.AF_INET6:
			ip = net.IP(row.Address.Addr[:])
		default:
			continue
		}
		out = append(out, Neighbor{ip.String(), row.State, row.PhysicalLength > 0, row.Flags&1 != 0, row.Flags&2 != 0})
		if len(out) > 32 {
			return nil, "TARGET_NEIGHBOR_LIMIT"
		}
	}
	return out, ""
}

func scopedEcho(source, destination net.IP, index uint32, multicast bool) EchoAttempt {
	r := EchoAttempt{Destination: destination.String(), InterfaceIndex: index}
	if index == 0 || source == nil || source.To4() != nil || !source.IsLinkLocalUnicast() || (!multicast && !eligibleIPv6Peer(destination, source)) || (multicast && !destination.Equal(net.ParseIP("ff02::1"))) {
		r.Error = "ECHO_SCOPE_OR_ADDRESS_INVALID"
		return r
	}
	dll := windows.NewLazySystemDLL("iphlpapi.dll")
	create := dll.NewProc("Icmp6CreateFile")
	send := dll.NewProc("Icmp6SendEcho2")
	parse := dll.NewProc("Icmp6ParseReplies")
	close := dll.NewProc("IcmpCloseHandle")
	for _, p := range []*windows.LazyProc{create, send, parse, close} {
		if p.Find() != nil {
			r.Error = "ECHO_API_UNAVAILABLE"
			return r
		}
	}
	h, _, e := create.Call()
	if h == 0 || h == ^uintptr(0) {
		r.Error = "ECHO_OPEN_" + eno(e)
		return r
	}
	defer close.Call(h)
	src := windows.RawSockaddrInet6{Family: windows.AF_INET6, Scope_id: index}
	dst := windows.RawSockaddrInet6{Family: windows.AF_INET6, Scope_id: index}
	copy(src.Addr[:], source.To16())
	copy(dst.Addr[:], destination.To16())
	nonce := make([]byte, 32)
	if _, e := rand.Read(nonce); e != nil {
		r.Error = "ECHO_NONCE_UNAVAILABLE"
		return r
	}
	reply := make([]byte, 4096)
	n, _, err := send.Call(h, 0, 0, 0, uintptr(unsafe.Pointer(&src)), uintptr(unsafe.Pointer(&dst)), uintptr(unsafe.Pointer(&nonce[0])), uintptr(len(nonce)), 0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), 1200)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(nonce)
	runtime.KeepAlive(reply)
	r.APIReplies = uint32(n)
	if n == 0 {
		r.Error = "ECHO_SEND_" + eno(err)
		return r
	}
	parsed, _, err := parse.Call(uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)))
	runtime.KeepAlive(reply)
	if parsed == 0 {
		r.Error = "ECHO_PARSE_" + eno(err)
		return r
	}
	r.APIParsed = true
	evidence := parseEchoReply(reply, nonce, source, destination, index, multicast)
	r.ReplyStatus = &evidence.Status
	if evidence.IP != nil {
		r.ReplyIP = evidence.IP.String()
	}
	r.ReplyScopeLE, r.ReplyScopeBE = evidence.ScopeLE, evidence.ScopeBE
	r.ReplyScopeReported = evidence.ScopeLE != 0
	r.NoncePayloadMatches = evidence.NonceMatches
	r.RTTMilliseconds = evidence.RTT
	r.EchoReplyVerified = evidence.Valid
	r.Error = evidence.Error
	return r
}

func (b *groupingBackend) currentPeerAdapter(expected string) (NetworkAdapter, string) {
	if b.directTarget != nil {
		ctx, cancel := context.WithTimeout(b.sessionContext(), 5*time.Second)
		defer cancel()
		s := inventory(ctx)
		if !b.directTarget.descriptorProof(s) {
			return NetworkAdapter{}, "DIRECT_CURRENT_DESCRIPTOR_PROOF_LOST"
		}
		return b.mappedPeerAdapter(s, expected)
	}
	s := Inspect()
	if !sameRootInstance(b.mode.Before, s) || !HasActiveNCM(s) {
		return NetworkAdapter{}, "PEER_TARGET_CHANGED_OR_NCM_LOST"
	}
	return b.mappedPeerAdapter(s, expected)
}

// A live session was already verified using USB descriptors and physical
// hub/port. Continue using fresh cached PnP physical paths plus the exact
// mapped adapter GUID/LUID. Never repeatedly open hubs during a stream.
func (b *groupingBackend) currentActivePeerAdapter(expected string) (NetworkAdapter, string) {
	ctx, cancel := context.WithTimeout(b.sessionContext(), 2*time.Second)
	defer cancel()
	s := inventoryPnP(ctx)
	ids := make([]string, 0, len(s.Nodes))
	var current, original *Node
	for i := range s.Nodes {
		n := &s.Nodes[i]
		ids = append(ids, n.instanceID)
		if strings.EqualFold(n.instanceID, b.networkRoot()) {
			current = n
		}
	}
	for i := range b.mode.Before.Nodes {
		n := &b.mode.Before.Nodes[i]
		if strings.EqualFold(n.instanceID, b.networkRoot()) {
			original = n
		}
	}
	if expected == "" || s.Error != "" || !idlePresenceFromIDs(ids, true).candidate || current == nil || original == nil ||
		!sameCachedLocation(original.locationPaths, current.locationPaths) || !grouptrial.NativeStartObserved(current.Problem, current.StateError, current.DevNodeStatus) {
		return NetworkAdapter{}, "ACTIVE_CACHED_PHYSICAL_TARGET_CHANGED_OR_UNCONFIRMED"
	}
	return b.mappedPeerAdapter(s, expected)
}

func (b *groupingBackend) mappedPeerAdapter(s Snapshot, expected string) (NetworkAdapter, string) {
	return b.mappedPeerAdapterFrom(s, expected, func() []NetworkAdapter { return readNCMAdapters(s) })
}

// Shared evaluator allows a read-only startup proof to reuse the already read
// exact-node mappings. All ordinary peer admission checks remain unchanged.
func (b *groupingBackend) mappedPeerAdapterFrom(s Snapshot, expected string, readAdapters func() []NetworkAdapter) (NetworkAdapter, string) {
	if b.directTarget != nil {
		return b.directTarget.mapping(s, expected, readAdapters)
	}
	if b.existingTarget != nil {
		return b.existingNetworkMapping(s, expected, readAdapters)
	}
	owned := false
	for _, n := range s.Nodes {
		if strings.EqualFold(n.instanceID, b.networkRoot()) && n.EnumeratorClass == "020000" && n.Problem == 0 && n.StateError == "" && !grouptrial.NeedsWindowsRestart(n.DevNodeStatus) {
			owned = true
		}
	}
	if !owned {
		return NetworkAdapter{}, "PEER_GROUPING_OR_ROOT_CHANGED"
	}
	var valid []NetworkAdapter
	for _, a := range readAdapters() {
		if a.Matched && a.StatisticsRead && a.Error == "" && a.OperStatus == 1 && a.MediaConnectState == 1 {
			valid = append(valid, a)
		}
	}
	if len(valid) != 1 {
		return NetworkAdapter{}, "PEER_NEEDS_ONE_CURRENT_MAPPED_CONNECTED_NCM_ADAPTER"
	}
	if expected != "" && valid[0].key != expected {
		return NetworkAdapter{}, "PEER_ADAPTER_IDENTITY_CHANGED"
	}
	return valid[0], ""
}

// Grouping consent explicitly covers these bounded scoped IPv6 packets. There
// are no IP, route, firewall, DHCP or pairing changes. No unsolicited WAN probes.
func (b *groupingBackend) probePeers() PeerProbe {
	r := PeerProbe{Consent: true, Status: "SCOPED_IPV6_PROBE_NO_VERIFIED_ECHO_NOT_SUPPORT_VERDICT"}
	a, err := b.currentPeerAdapter("")
	if err != "" {
		r.Status = err
		return r
	}
	r.InterfaceIndex = a.InterfaceIndex
	r.NeighborsBefore, r.NeighborError = targetNeighbors(a)
	var source net.IP
	for _, addr := range a.Addresses {
		ip := net.ParseIP(addr.IP)
		if addr.DadState == 4 && ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
			source = ip
			break
		}
	}
	if source == nil || a.IPv6InterfaceIndex == 0 {
		r.Status = "PREFERRED_TARGET_IPV6_LINK_LOCAL_SOURCE_UNAVAILABLE"
		return r
	}
	key := a.key
	scope := a.IPv6InterfaceIndex
	r.adapterKey, r.sourceIPv6, r.ipv6Scope = key, source.String(), scope
	own := map[string]bool{}
	for _, addr := range a.Addresses {
		own[addr.IP] = true
	}
	candidates := []net.IP{}
	seen := map[string]bool{}
	add := func(ip net.IP) {
		if eligibleIPv6Peer(ip, source) && !own[ip.String()] && !seen[ip.String()] && len(candidates) < 4 {
			seen[ip.String()] = true
			candidates = append(candidates, ip)
		}
	}
	for _, n := range r.NeighborsBefore {
		if !n.Unreachable && n.LinkAddressPresent {
			add(net.ParseIP(n.IP))
		}
	}
	// Link-local multicast discovery is one small request on this interface only.
	fresh, err := b.currentPeerAdapter(key)
	if err != "" {
		r.Status = err
		return r
	}
	if !probeSourcePresent(fresh, source, scope) {
		r.Status = "PEER_IPV6_SCOPE_CHANGED"
		return r
	}
	discovery := scopedEcho(source, net.ParseIP("ff02::1"), scope, true)
	if discovery.EchoReplyVerified {
		after, e := b.currentPeerAdapter(key)
		if e != "" || !probeSourcePresent(after, source, scope) || probeAddressLocal(after, net.ParseIP(discovery.ReplyIP)) {
			discovery.Error = "TARGET_CHANGED_DURING_DISCOVERY_REPLY"
			r.Echoes = append(r.Echoes, discovery)
			r.Status = discovery.Error
			return r
		}
		discovery.TargetStableAfter = true
		discovery.ScopedNonceRoundtrip = true
	}
	r.Echoes = append(r.Echoes, discovery)
	if discovery.ScopedNonceRoundtrip {
		add(net.ParseIP(discovery.ReplyIP))
	}
	r.NeighborsAfter, err = targetNeighbors(fresh)
	if err != "" {
		r.NeighborError = err
	}
	for _, n := range r.NeighborsAfter {
		if !n.Unreachable && n.LinkAddressPresent {
			add(net.ParseIP(n.IP))
		}
	}
	for _, peer := range candidates {
		for attempt := 0; attempt < 3; attempt++ {
			fresh, err = b.currentPeerAdapter(key)
			if err != "" {
				r.Status = err
				return r
			}
			if probeAddressLocal(fresh, peer) {
				r.Echoes = append(r.Echoes, EchoAttempt{Destination: peer.String(), InterfaceIndex: scope, Error: "CANDIDATE_IS_CURRENT_LOCAL_ADDRESS_NO_REQUEST"})
				break
			}
			sourceStillPresent := false
			for _, addr := range fresh.Addresses {
				if addr.DadState == 4 && net.ParseIP(addr.IP).Equal(source) {
					sourceStillPresent = true
				}
			}
			if !sourceStillPresent || fresh.IPv6InterfaceIndex != scope {
				r.Status = "PEER_SOURCE_OR_SCOPE_CHANGED"
				return r
			}
			echo := scopedEcho(source, peer, scope, false)
			if echo.EchoReplyVerified {
				after, e := b.currentPeerAdapter(key)
				if e != "" || !probeSourcePresent(after, source, scope) || probeAddressLocal(after, peer) {
					echo.Error = "TARGET_CHANGED_DURING_UNICAST_REPLY"
					r.Echoes = append(r.Echoes, echo)
					r.Status = echo.Error
					return r
				}
				echo.TargetStableAfter = true
				echo.ScopedNonceRoundtrip = true
				r.IPv6EchoVerified = true
			}
			r.Echoes = append(r.Echoes, echo)
		}
	}
	if r.IPv6EchoVerified {
		r.Status = "TARGET_SCOPED_UNICAST_IPV6_NONCE_ECHO_VERIFIED_NOT_MOONLIGHT_PROOF"
	}
	return r
}

func probeSourcePresent(a NetworkAdapter, source net.IP, scope uint32) bool {
	if a.IPv6InterfaceIndex != scope {
		return false
	}
	for _, addr := range a.Addresses {
		if addr.DadState == 4 && net.ParseIP(addr.IP).Equal(source) {
			return true
		}
	}
	return false
}

func probeAddressLocal(a NetworkAdapter, ip net.IP) bool {
	for _, addr := range a.Addresses {
		if net.ParseIP(addr.IP).Equal(ip) {
			return true
		}
	}
	return false
}

// Let address and neighbor discovery settle on the running adapter. A late
// IPv6 source must not cause a full grouping rollback and cable-replug prompt.
func (b *groupingBackend) waitForPeerReady() PeerProbe {
	ctx := b.sessionContext()
	deadline := time.Now().Add(45 * time.Second)
	var peer PeerProbe
	for attempt := 0; attempt < 4; attempt++ {
		if ctx.Err() != nil {
			return PeerProbe{Status: "PEER_PREPARATION_CANCELLED"}
		}
		if s := connectionMonitor(); s != nil {
			s.update(func(r *ApplicationResult) { r.Status = "IPAD_WAITING_PEER_ADDRESS" })
		}
		peer = b.probePeers()
		if peer.IPv6EchoVerified || !peerPreparationRetryable(peer.Status) || attempt == 3 || time.Now().After(deadline) {
			return peer
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return PeerProbe{Status: "PEER_PREPARATION_CANCELLED"}
		case <-timer.C:
		}
	}
	return peer
}
