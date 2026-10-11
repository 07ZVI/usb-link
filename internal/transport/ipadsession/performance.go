package ipadsession

import "math"

// Interface counters cannot measure packets lost after delivery to iPad or
// decoder/rendering drops. Keep them explicitly separate from Moonlight loss.
type InterfaceFaults struct {
	InErrors    uint64 `json:"in_errors"`
	OutErrors   uint64 `json:"out_errors"`
	InDiscards  uint64 `json:"in_discards"`
	OutDiscards uint64 `json:"out_discards"`
}

func (n InterfaceFaults) Delta(p InterfaceFaults) (InterfaceFaults, bool) {
	if n.InErrors < p.InErrors || n.OutErrors < p.OutErrors || n.InDiscards < p.InDiscards || n.OutDiscards < p.OutDiscards {
		return InterfaceFaults{}, false
	}
	return InterfaceFaults{n.InErrors - p.InErrors, n.OutErrors - p.OutErrors, n.InDiscards - p.InDiscards, n.OutDiscards - p.OutDiscards}, true
}

const PerformanceHistoryLimit = 600

type PerformanceSample struct {
	RecordedUTC     string          `json:"recorded_utc,omitempty"`
	ElapsedMS       int64           `json:"elapsed_ms"`
	IntervalMS      float64         `json:"counter_interval_ms"`
	QueryMS         float64         `json:"cached_target_query_ms_not_packet_latency"`
	TransmitMbps    float64         `json:"transmit_mbps"`
	ReceiveMbps     float64         `json:"receive_mbps"`
	FaultDeltaValid bool            `json:"interface_fault_delta_valid"`
	Faults          InterfaceFaults `json:"windows_interface_fault_delta_not_moonlight_loss"`
}

type Performance struct {
	FaultEvents        []PerformanceSample `json:"latest_interface_fault_events,omitempty"`
	Samples            uint64              `json:"samples"`
	HistoryOmitted     uint64              `json:"older_samples_omitted"`
	FaultCounterResets uint64              `json:"fault_counter_resets"`
	Faults             InterfaceFaults     `json:"windows_interface_session_faults_not_moonlight_loss"`
	MaxQueryMS         float64             `json:"max_cached_target_query_ms_not_packet_latency"`
	MaxIntervalMS      float64             `json:"max_counter_interval_ms"`
	History            []PerformanceSample `json:"latest_samples,omitempty"`
}

func (p *Performance) Record(s PerformanceSample) {
	// Never export invalid rates or let malformed measurements poison JSON.
	if s.ElapsedMS < 0 || s.IntervalMS <= 0 || s.QueryMS < 0 || s.TransmitMbps < 0 || s.ReceiveMbps < 0 {
		return
	}
	for _, x := range []float64{s.IntervalMS, s.QueryMS, s.TransmitMbps, s.ReceiveMbps} {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return
		}
	}
	if s.FaultDeltaValid && (s.Faults.InErrors > 0 || s.Faults.OutErrors > 0 || s.Faults.InDiscards > 0 || s.Faults.OutDiscards > 0) {
		if len(p.FaultEvents) == 64 {
			copy(p.FaultEvents, p.FaultEvents[1:])
			p.FaultEvents = p.FaultEvents[:63]
		}
		p.FaultEvents = append(p.FaultEvents, s)
	}
	p.Samples++
	p.MaxQueryMS = max(p.MaxQueryMS, s.QueryMS)
	p.MaxIntervalMS = max(p.MaxIntervalMS, s.IntervalMS)
	if s.FaultDeltaValid {
		p.Faults.InErrors += s.Faults.InErrors
		p.Faults.OutErrors += s.Faults.OutErrors
		p.Faults.InDiscards += s.Faults.InDiscards
		p.Faults.OutDiscards += s.Faults.OutDiscards
	} else {
		p.FaultCounterResets++
		s.Faults = InterfaceFaults{}
	}
	if len(p.History) == PerformanceHistoryLimit {
		copy(p.History, p.History[1:])
		p.History[len(p.History)-1] = s
		p.HistoryOmitted++
	} else {
		p.History = append(p.History, s)
	}
}

func (p Performance) Snapshot() Performance {
	p.History = append([]PerformanceSample(nil), p.History...)
	p.FaultEvents = append([]PerformanceSample(nil), p.FaultEvents...)
	return p
}
