package ipadncm

import (
	"sync"
	"time"
)

// Read-only USB network diagnostics for remote debugging. Everything here is
// observation only: nothing gates readiness or changes system state.

type NetDebugEvent struct {
	UTC    string `json:"utc"`
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

type NetDebugInterface struct {
	Index            uint32 `json:"index"`
	Alias            string `json:"alias"`
	OperStatus       string `json:"oper_status"`
	MediaConnect     string `json:"media_connect"`
	InOctets         uint64 `json:"in_octets"`
	OutOctets        uint64 `json:"out_octets"`
	InUcastPkts      uint64 `json:"in_ucast_pkts"`
	OutUcastPkts     uint64 `json:"out_ucast_pkts"`
	InDiscards       uint64 `json:"in_discards"`
	InErrors         uint64 `json:"in_errors"`
	OutDiscards      uint64 `json:"out_discards"`
	OutErrors        uint64 `json:"out_errors"`
	IPv4Readable     bool   `json:"ipv4_interface_readable"`
	Connected        bool   `json:"ipv4_connected"`
	Forwarding       bool   `json:"forwarding"`
	WeakHostSend     bool   `json:"weak_host_send"`
	WeakHostReceive  bool   `json:"weak_host_receive"`
	UseNUD           bool   `json:"neighbor_unreachability_detection"`
	DadTransmits     uint32 `json:"dad_transmits"`
	NlMtu            uint32 `json:"nl_mtu"`
	ReachableTimeMS  uint32 `json:"reachable_time_ms"`
	BaseReachableMS  uint32 `json:"base_reachable_time_ms"`
	RetransmitTimeMS uint32 `json:"retransmit_time_ms"`
	Metric           uint32 `json:"metric"`
}

type NetDebugAddress struct {
	Index        uint32 `json:"index"`
	IP           string `json:"ip"`
	Prefix       uint8  `json:"prefix"`
	DadState     string `json:"dad_state"`
	SkipAsSource bool   `json:"skip_as_source"`
}

type NetDebugNeighbor struct {
	Index uint32 `json:"index"`
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	State string `json:"state"`
}

type NetDebugRoute struct {
	Index   uint32 `json:"index"`
	Prefix  string `json:"prefix"`
	NextHop string `json:"next_hop"`
	Metric  uint32 `json:"metric"`
}

type NetDebugSnapshot struct {
	UTC        string              `json:"utc"`
	Reason     string              `json:"reason"`
	Interfaces []NetDebugInterface `json:"interfaces"`
	Addresses  []NetDebugAddress   `json:"addresses"`
	Neighbors  []NetDebugNeighbor  `json:"neighbors"`
	Routes     []NetDebugRoute     `json:"routes"`
	Error      string              `json:"error,omitempty"`
}

type NetDebugCounter struct {
	UTC       string `json:"utc"`
	InPkts    uint64 `json:"in_ucast_pkts"`
	OutPkts   uint64 `json:"out_ucast_pkts"`
	InOctets  uint64 `json:"in_octets"`
	OutOctets uint64 `json:"out_octets"`
}

type NetDebugExport struct {
	Counters  []NetDebugCounter  `json:"ipad_interface_counters_2s"`
	Scope     string             `json:"scope"`
	PeerState string             `json:"peer_neighbor_state"`
	Events    []NetDebugEvent    `json:"events"`
	Latest    *NetDebugSnapshot  `json:"latest_snapshot,omitempty"`
	Captured  []NetDebugSnapshot `json:"captured_snapshots"`
}

const (
	netDebugMaxEvents    = 120
	netDebugMaxSnapshots = 6
)

type netDebugLog struct {
	mu        sync.Mutex
	events    []NetDebugEvent
	captured  []NetDebugSnapshot
	latest    *NetDebugSnapshot
	peerState string
	counters  []NetDebugCounter
}

func (l *netDebugLog) counter(c NetDebugCounter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c.UTC = netDebugNow()
	l.counters = append(l.counters, c)
	if len(l.counters) > 90 {
		l.counters = append([]NetDebugCounter(nil), l.counters[len(l.counters)-90:]...)
	}
}

var ipadNetDebug = &netDebugLog{}

func netDebugNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }

func (l *netDebugLog) event(kind, detail string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, NetDebugEvent{UTC: netDebugNow(), Kind: kind, Detail: detail})
	if len(l.events) > netDebugMaxEvents {
		l.events = append([]NetDebugEvent(nil), l.events[len(l.events)-netDebugMaxEvents:]...)
	}
}

// peer records the raw neighbor state for the peer and logs every transition.
func (l *netDebugLog) peer(state string) bool {
	l.mu.Lock()
	changed := state != l.peerState
	previous := l.peerState
	l.peerState = state
	l.mu.Unlock()
	if changed {
		l.event("peer_neighbor_state", previous+" -> "+state)
	}
	return changed
}

func (l *netDebugLog) store(s NetDebugSnapshot, capture bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	copySnapshot := s
	l.latest = &copySnapshot
	if capture {
		l.captured = append(l.captured, s)
		if len(l.captured) > netDebugMaxSnapshots {
			l.captured = append([]NetDebugSnapshot(nil), l.captured[len(l.captured)-netDebugMaxSnapshots:]...)
		}
	}
}

func (l *netDebugLog) export() NetDebugExport {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := NetDebugExport{Scope: "read-only USB network observation; never gates readiness", PeerState: l.peerState,
		Events: append([]NetDebugEvent{}, l.events...), Counters: append([]NetDebugCounter{}, l.counters...), Captured: append([]NetDebugSnapshot{}, l.captured...)}
	if l.latest != nil {
		s := *l.latest
		out.Latest = &s
	}
	return out
}

func neighborStateName(s uint32) string {
	switch s {
	case 0:
		return "unreachable"
	case 1:
		return "incomplete"
	case 2:
		return "probe"
	case 3:
		return "delay"
	case 4:
		return "stale"
	case 5:
		return "reachable"
	case 6:
		return "permanent"
	}
	return "unknown"
}

func dadStateName(s uint32) string {
	switch s {
	case 0:
		return "invalid"
	case 1:
		return "tentative"
	case 2:
		return "duplicate"
	case 3:
		return "deprecated"
	case 4:
		return "preferred"
	}
	return "unknown"
}

func operStatusName(s uint32) string {
	switch s {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 4:
		return "unknown"
	case 5:
		return "dormant"
	case 6:
		return "not_present"
	case 7:
		return "lower_layer_down"
	}
	return "unknown"
}

func mediaConnectName(s uint32) string {
	switch s {
	case 1:
		return "connected"
	case 2:
		return "disconnected"
	}
	return "unknown"
}
