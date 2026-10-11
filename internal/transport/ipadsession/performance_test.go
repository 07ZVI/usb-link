package ipadsession

import (
	"math"
	"testing"
)

func TestFaultDeltaRejectsResetAndIgnoresExistingCounters(t *testing.T) {
	p := InterfaceFaults{InErrors: 50, OutErrors: 60, InDiscards: 70, OutDiscards: 80}
	n := InterfaceFaults{InErrors: 51, OutErrors: 63, InDiscards: 75, OutDiscards: 87}
	d, ok := n.Delta(p)
	if !ok || d != (InterfaceFaults{1, 3, 5, 7}) {
		t.Fatal(d, ok)
	}
	n.InErrors = 0
	if d, ok := n.Delta(p); ok || d != (InterfaceFaults{}) {
		t.Fatal("reset became a large unsigned loss", d, ok)
	}
}

func TestPerformanceRetainsBoundsAndTotalsAfterHistoryEviction(t *testing.T) {
	var p Performance
	for i := 0; i < PerformanceHistoryLimit+3; i++ {
		p.Record(PerformanceSample{ElapsedMS: int64(i) * 1000, IntervalMS: 1000, QueryMS: float64(i), TransmitMbps: 400, FaultDeltaValid: true, Faults: InterfaceFaults{OutDiscards: 2}})
	}
	if len(p.History) != PerformanceHistoryLimit || p.HistoryOmitted != 3 || p.History[0].ElapsedMS != 3000 || p.Faults.OutDiscards != uint64(2*(PerformanceHistoryLimit+3)) {
		t.Fatal(p)
	}
	s := p.Snapshot()
	p.Record(PerformanceSample{ElapsedMS: 1000000, IntervalMS: 2500, FaultDeltaValid: false, Faults: InterfaceFaults{OutDiscards: 9999}})
	if s.History[0].ElapsedMS != 3000 || p.FaultCounterResets != 1 || p.MaxIntervalMS != 2500 || p.Faults.OutDiscards != s.Faults.OutDiscards {
		t.Fatal("snapshot alias, reset or cumulative fault error")
	}
	s.History[0].ElapsedMS = 0
	if p.History[0].ElapsedMS == 0 {
		t.Fatal("snapshot aliases live history")
	}
}

func TestPerformanceRejectsInvalidMeasurements(t *testing.T) {
	var p Performance
	for _, s := range []PerformanceSample{{IntervalMS: math.NaN()}, {IntervalMS: 1000, QueryMS: math.Inf(1)}, {IntervalMS: 1000, TransmitMbps: -1}, {IntervalMS: 0}} {
		p.Record(s)
	}
	if p.Samples != 0 || len(p.History) != 0 {
		t.Fatal(p)
	}
}

func TestFaultEventsSurviveQuietHistoryEviction(t *testing.T) {
	var p Performance
	p.Record(PerformanceSample{RecordedUTC: "2026-10-03T00:00:00Z", IntervalMS: 1000, FaultDeltaValid: true, Faults: InterfaceFaults{OutDiscards: 7}})
	for i := 0; i < PerformanceHistoryLimit+5; i++ {
		p.Record(PerformanceSample{IntervalMS: 1000, FaultDeltaValid: true})
	}
	if len(p.FaultEvents) != 1 || p.FaultEvents[0].Faults.OutDiscards != 7 || p.FaultEvents[0].RecordedUTC == "" {
		t.Fatal("fault evidence evicted")
	}
	snap := p.Snapshot()
	snap.FaultEvents[0].Faults.OutDiscards = 999
	if p.FaultEvents[0].Faults.OutDiscards != 7 {
		t.Fatal("fault snapshot aliases live state")
	}
}
