package netconfig

import (
	"sort"
	"sync"
	"time"
)

// Only fixed operation names enter this process-local diagnostic. Counts and
// durations contain no interface identity, executable path or provider error.
var networkTimingNames = map[string]bool{
	"firewall_provider_preflight": true, "mac_subnet_conflict": true,
	"mac_interface": true, "mac_address": true, "mac_peer_route": true,
	"mac_adapter_close_settle": true, "mac_adapter_absence": true,
	"os_icmp": true, "private_profile_read": true, "private_profile_set": true,
	"private_profile_recovery_read": true,
	"marked_firewall_cleanup":       true, "firewall_rules": true, "firewall_cleanup": true,
	"shared_host_firewall": true, "legacy_network_script": true, "ipad_address_diagnostic_script": true,
	"remote_legacy_cleanup": true, "remote_coverage_read": true,
	"legacy_shared_host_script": true, "legacy_mac_services_script": true,
	"legacy_ipad_permissions_script": true, "legacy_mac_recovery_script": true,
}

type NativeOperationTiming struct {
	Operation    string  `json:"operation"`
	Count        uint64  `json:"count"`
	Failures     uint64  `json:"failures"`
	InFlight     uint64  `json:"in_flight"`
	LastBeginUTC string  `json:"last_begin_utc,omitempty"`
	LastEndUTC   string  `json:"last_end_utc,omitempty"`
	LastMS       float64 `json:"last_ms"`
	CumulativeMS float64 `json:"cumulative_ms"`
}

var networkTimings = struct {
	sync.Mutex
	rows map[string]NativeOperationTiming
}{rows: make(map[string]NativeOperationTiming)}

func beginNetworkTiming(operation string) func(error) {
	if !networkTimingNames[operation] {
		return func(error) {}
	}
	start := time.Now()
	networkTimings.Lock()
	row := networkTimings.rows[operation]
	row.Operation, row.Count, row.InFlight = operation, row.Count+1, row.InFlight+1
	networkTimings.rows[operation] = row
	networkTimings.Unlock()
	var once sync.Once
	return func(err error) {
		once.Do(func() {
			end := time.Now()
			elapsed := float64(end.Sub(start)) / float64(time.Millisecond)
			networkTimings.Lock()
			defer networkTimings.Unlock()
			row := networkTimings.rows[operation]
			row.InFlight--
			if err != nil {
				row.Failures++
			}
			row.LastBeginUTC, row.LastEndUTC = start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano)
			row.LastMS, row.CumulativeMS = elapsed, row.CumulativeMS+elapsed
			networkTimings.rows[operation] = row
		})
	}
}

// NativeOperationTimingsSnapshot reports this process only. Bridge timings
// remain bridge-local and in its fixed phase log. Nested operations overlap:
// callers must compare the same operation across runs, not sum every row.
func NativeOperationTimingsSnapshot() []NativeOperationTiming {
	networkTimings.Lock()
	defer networkTimings.Unlock()
	rows := make([]NativeOperationTiming, 0, len(networkTimings.rows))
	for _, row := range networkTimings.rows {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Operation < rows[j].Operation })
	return rows
}

// NativeOperationValid accepts only this compiled process-local vocabulary.
func NativeOperationValid(operation string) bool {
	return networkTimingNames[operation] || macStartupOperationValid(operation)
}
