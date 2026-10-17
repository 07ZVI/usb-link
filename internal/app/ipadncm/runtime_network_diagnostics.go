package ipadncm

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

const runtimeNetworkInterval = 10 * time.Second
const runtimeNetworkBudget = 2 * time.Second
const runtimeNetworkAdapterLimit = 2
const runtimeNetworkAddressLimit = 2
const runtimeNetworkTCPMatchLimit = 4

type RuntimeNetworkAdapter struct {
	Index            uint32   `json:"index,omitempty"`
	OperStatus       uint32   `json:"oper_status"`
	IPv4             []string `json:"ipv4,omitempty"`
	AddressesOmitted int      `json:"addresses_omitted,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type RuntimeNetworkTCPMatch struct {
	Kind   string `json:"kind"`
	Local  string `json:"local"`
	Remote string `json:"remote,omitempty"`
	State  string `json:"state"`
}

type RuntimeNetworkTCP struct {
	Status               string                   `json:"status"`
	SunshineEstablished  bool                     `json:"sunshine_default_port_established"`
	LocalSendListening   bool                     `json:"localsend_default_port_listening"`
	LocalSendEstablished bool                     `json:"localsend_default_port_established"`
	Matches              []RuntimeNetworkTCPMatch `json:"matches,omitempty"`
	MatchesOmitted       int                      `json:"matches_omitted,omitempty"`
}

// Port numbers identify an observable endpoint, not its process or successful
// application traffic. TCP address pairs do not prove the route taken by packets.
type RuntimeNetworkDiagnostic struct {
	Status          string                  `json:"status"`
	SampledUTC      string                  `json:"sampled_utc,omitempty"`
	AgeMS           int64                   `json:"age_ms"`
	Stale           bool                    `json:"stale"`
	Collecting      bool                    `json:"collecting"`
	ElapsedMS       int64                   `json:"elapsed_ms"`
	BudgetExceeded  bool                    `json:"budget_exceeded"`
	Adapters        []RuntimeNetworkAdapter `json:"root_scoped_ncm_adapters,omitempty"`
	AdaptersOmitted int                     `json:"adapters_omitted,omitempty"`
	TCP             RuntimeNetworkTCP       `json:"ipv4_tcp"`
	IPv6Observed    bool                    `json:"ipv6_observed"`
	ProcessVerified bool                    `json:"process_identity_verified"`
	RouteVerified   bool                    `json:"route_verified"`
}

type runtimeNetworkCache struct {
	sync.Mutex
	value               RuntimeNetworkDiagnostic
	sampled, started    time.Time
	running, collecting bool
}

var runtimeNetworkState runtimeNetworkCache

// Start once from the locally-enabled diagnostics owner, not a connection session.
// One worker performs synchronous native reads; a stuck read never spawns another
// worker or blocks the cached log/UI reader. The budget is checked between reads.
func StartRuntimeNetworkDiagnostics(ctx context.Context) {
	startRuntimeNetworkDiagnostics(ctx, &runtimeNetworkState, collectRuntimeNetworkDiagnostics, runtimeNetworkInterval)
}

func startRuntimeNetworkDiagnostics(ctx context.Context, cache *runtimeNetworkCache, collect func(context.Context) RuntimeNetworkDiagnostic, interval time.Duration) {
	cache.Lock()
	if cache.running {
		cache.Unlock()
		return
	}
	cache.running = true
	cache.Unlock()
	go func() {
		defer func() { cache.Lock(); cache.running = false; cache.collecting = false; cache.Unlock() }()
		for ctx.Err() == nil {
			started := time.Now()
			cache.Lock()
			cache.collecting = true
			cache.started = started
			cache.Unlock()
			budget, cancel := context.WithTimeout(ctx, runtimeNetworkBudget)
			value := collect(budget)
			value.BudgetExceeded = budget.Err() != nil || time.Since(started) > runtimeNetworkBudget
			cancel()
			value.SampledUTC = started.UTC().Format(time.RFC3339)
			value.ElapsedMS = time.Since(started).Milliseconds()
			cache.Lock()
			cache.value = value
			cache.sampled = started
			cache.collecting = false
			cache.Unlock()
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func RuntimeNetworkDiagnostics() RuntimeNetworkDiagnostic {
	return runtimeNetworkState.snapshot(time.Now())
}

func (cache *runtimeNetworkCache) snapshot(now time.Time) RuntimeNetworkDiagnostic {
	cache.Lock()
	defer cache.Unlock()
	value := cache.value
	if cache.sampled.IsZero() {
		value.Status = "NOT_SAMPLED"
		value.Stale = true
	} else {
		value.AgeMS = max(0, now.Sub(cache.sampled).Milliseconds())
		value.Stale = now.Sub(cache.sampled) > 2*runtimeNetworkInterval || value.BudgetExceeded
	}
	value.Collecting = cache.collecting
	if cache.collecting && now.Sub(cache.started) > runtimeNetworkBudget {
		value.Stale = true
		value.BudgetExceeded = true
	}
	value.Adapters = append([]RuntimeNetworkAdapter(nil), value.Adapters...)
	for i := range value.Adapters {
		value.Adapters[i].IPv4 = append([]string(nil), value.Adapters[i].IPv4...)
	}
	value.TCP.Matches = append([]RuntimeNetworkTCPMatch(nil), value.TCP.Matches...)
	return value
}

type runtimeNetworkPair struct{ local, peer netip.Addr }

// Accept only known USB Link profiles already present on this exact NCM adapter.
// Shared-host .1 may live on another interface; this remains address-pair evidence.
func runtimeNetworkPairs(addresses []string) []runtimeNetworkPair {
	var pairs []runtimeNetworkPair
	add := func(local, peer netip.Addr) {
		p := runtimeNetworkPair{local, peer}
		for _, old := range pairs {
			if old == p {
				return
			}
		}
		pairs = append(pairs, p)
	}
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		a := prefix.Addr().As4()
		switch {
		case a == [4]byte{10, 6, 9, 254}:
			add(netip.AddrFrom4(a), netip.AddrFrom4([4]byte{10, 6, 9, 3}))
			add(netip.AddrFrom4([4]byte{10, 6, 9, 1}), netip.AddrFrom4([4]byte{10, 6, 9, 3}))
		case a == [4]byte{10, 6, 9, 1}:
			add(netip.AddrFrom4(a), netip.AddrFrom4([4]byte{10, 6, 9, 3}))
		case a == [4]byte{10, 6, 10, 1} || a[0] == 10 && a[1] == 77 && a[2] > 0 && a[2] < 255 && a[3] == 1:
			a[3] = 2
			add(prefix.Addr(), netip.AddrFrom4(a))
		}
	}
	return pairs
}

// MIB_TCPROW_OWNER_PID is 24 bytes. Do not retain PIDs, unrelated sockets or LAN IPs.
func runtimeNetworkTCP(table []byte, pairs []runtimeNetworkPair) RuntimeNetworkTCP {
	r := RuntimeNetworkTCP{Status: "READ"}
	if len(table) < 4 {
		r.Status = "TABLE_INVALID"
		return r
	}
	n := binary.LittleEndian.Uint32(table[:4])
	if n > 16384 || uint64(n)*24 > uint64(len(table)-4) {
		r.Status = "TABLE_INVALID"
		return r
	}
	add := func(m RuntimeNetworkTCPMatch) {
		for _, old := range r.Matches {
			if old == m {
				return
			}
		}
		if len(r.Matches) >= runtimeNetworkTCPMatchLimit {
			r.MatchesOmitted++
			return
		}
		r.Matches = append(r.Matches, m)
	}
	for i := uint32(0); i < n; i++ {
		row := table[4+i*24 : 4+(i+1)*24]
		state := binary.LittleEndian.Uint32(row)
		local, peer := netip.AddrFrom4([4]byte(row[4:8])), netip.AddrFrom4([4]byte(row[12:16]))
		port, remotePort := binary.BigEndian.Uint16(row[8:10]), binary.BigEndian.Uint16(row[16:18])
		localMatch, pairMatch := false, false
		for _, p := range pairs {
			if p.local == local {
				localMatch = true
				if p.peer == peer {
					pairMatch = true
				}
			}
		}
		if state == 2 && port == 53317 && (local.IsUnspecified() || localMatch) {
			r.LocalSendListening = true
			add(RuntimeNetworkTCPMatch{Kind: "localsend_default_port", Local: netip.AddrPortFrom(local, port).String(), State: "listen_not_reachability_proof"})
		}
		if state != 5 || !pairMatch {
			continue
		}
		kind := ""
		if port == 47984 || port == 47989 || port == 48010 {
			r.SunshineEstablished = true
			kind = "sunshine_default_port"
		}
		if port == 53317 || remotePort == 53317 {
			r.LocalSendEstablished = true
			kind = "localsend_default_port"
		}
		if kind != "" {
			add(RuntimeNetworkTCPMatch{Kind: kind, Local: netip.AddrPortFrom(local, port).String(), Remote: netip.AddrPortFrom(peer, remotePort).String(), State: "established"})
		}
	}
	return r
}
