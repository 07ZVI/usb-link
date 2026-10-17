// Package shutdowntrace measures bounded cleanup intervals, not recovery proof.
package shutdowntrace

import (
	"sync"
	"time"
)

type Phase string

const (
	PhaseApplicationJoin      Phase = "application_join"
	PhaseMacBridgeStop        Phase = "mac_bridge_stop"
	PhaseMacServicesStop      Phase = "mac_services_stop"
	PhaseMacSessionRecovery   Phase = "mac_session_recovery"
	PhaseMacMTURestore        Phase = "mac_mtu_restore"
	PhaseMacRecoveryLock      Phase = "mac_recovery_lock"
	PhaseMacRecoveryRules     Phase = "mac_recovery_rules"
	PhaseMacRecoveryAdapter   Phase = "mac_recovery_adapter"
	PhaseMacRecoveryScript    Phase = "mac_recovery_script"
	PhaseDefaultIsolationStop Phase = "default_isolation_stop"
	PhaseWPDStop              Phase = "wpd_stop"
	PhaseUSBStop              Phase = "usb_stop"
	PhasePnPStop              Phase = "pnp_stop"
	PhaseDirectStop           Phase = "direct_stop"
	PhaseEnvironmentStop      Phase = "environment_stop"
	PhaseIPadSessionRecovery  Phase = "ipad_session_recovery"
	PhaseIPadFirewallRestore  Phase = "ipad_firewall_restore"
	PhaseIPadDADRestore       Phase = "ipad_dad_restore"
	PhaseIPadRouteRestore     Phase = "ipad_route_restore"
	PhaseIPadAddressRestore   Phase = "ipad_address_restore"
	PhaseIPadHostFlagsRestore Phase = "ipad_host_flags_restore"
	PhaseUIStop               Phase = "ui_stop"
	PhaseSchemaJoin           Phase = "schema_join"
	PhaseMacJoin              Phase = "mac_join"
)

func valid(p Phase) bool {
	switch p {
	case PhaseMacRecoveryLock, PhaseMacRecoveryRules, PhaseMacRecoveryAdapter, PhaseMacRecoveryScript, PhaseApplicationJoin, PhaseMacBridgeStop, PhaseMacServicesStop, PhaseMacSessionRecovery, PhaseMacMTURestore, PhaseDefaultIsolationStop, PhaseWPDStop, PhaseUSBStop, PhasePnPStop, PhaseDirectStop, PhaseEnvironmentStop, PhaseIPadSessionRecovery, PhaseIPadFirewallRestore, PhaseIPadDADRestore, PhaseIPadRouteRestore, PhaseIPadAddressRestore, PhaseIPadHostFlagsRestore, PhaseUIStop, PhaseSchemaJoin, PhaseMacJoin:
		return true
	}
	return false
}

type Interval struct {
	Phase     Phase `json:"phase"`
	BeginMS   int64 `json:"begin_ms"`
	ElapsedMS int64 `json:"elapsed_ms"`
	Complete  bool  `json:"complete"`
}

type Status struct {
	StartedUTC string     `json:"started_utc,omitempty"`
	Intervals  []Interval `json:"intervals,omitempty"`
	Omitted    uint64     `json:"omitted"`
}

type recorder struct {
	mu         sync.Mutex
	start      time.Time
	generation uint64
	intervals  []Interval
	omitted    uint64
}

var current recorder

// Start is called once, immediately before cancelling the application owner.
func Start() { current.startAt(time.Now()) }

func (r *recorder) startAt(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.start, r.intervals, r.omitted = now, nil, 0
	r.generation++
}

func Begin(phase Phase) func() {
	return current.beginAt(phase, time.Now(), time.Now)
}

func (r *recorder) beginAt(phase Phase, now time.Time, clock func() time.Time) func() {
	r.mu.Lock()
	if r.start.IsZero() || !valid(phase) {
		r.mu.Unlock()
		return func() {}
	}
	if len(r.intervals) == 32 {
		r.omitted++
		r.mu.Unlock()
		return func() {}
	}
	index, generation := len(r.intervals), r.generation
	r.intervals = append(r.intervals, Interval{Phase: phase, BeginMS: max(0, now.Sub(r.start).Milliseconds())})
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			end := clock()
			r.mu.Lock()
			defer r.mu.Unlock()
			if generation == r.generation {
				r.intervals[index].ElapsedMS = max(0, end.Sub(now).Milliseconds())
				r.intervals[index].Complete = true
			}
		})
	}
}

func Snapshot() Status { return current.snapshot() }

func (r *recorder) snapshot() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Status{Intervals: append([]Interval(nil), r.intervals...), Omitted: r.omitted}
	if !r.start.IsZero() {
		s.StartedUTC = r.start.UTC().Format(time.RFC3339Nano)
	}
	return s
}

// Wrap defers the interval until stop actually runs, not worker startup.
func Wrap(phase Phase, stop func()) func() {
	return func() { end := Begin(phase); defer end(); stop() }
}

// ValidSnapshot validates only the fixed diagnostic vocabulary, never cleanup success.
func ValidSnapshot(s Status) bool {
	t, e := time.Parse(time.RFC3339Nano, s.StartedUTC)
	if e != nil || t.UTC().Format(time.RFC3339Nano) != s.StartedUTC || len(s.Intervals) > 32 {
		return false
	}
	for _, i := range s.Intervals {
		if !valid(i.Phase) || i.BeginMS < 0 || i.ElapsedMS < 0 {
			return false
		}
	}
	return true
}
