package shutdowntrace

import (
	"encoding/json"
	"testing"
	"time"
)

func TestInactiveAndUnknownPhasesDoNotCapture(t *testing.T) {
	var r recorder
	now := time.Unix(1, 0)
	r.beginAt(PhaseMacJoin, now, func() time.Time { return now })()
	r.startAt(now)
	r.beginAt(Phase("private arbitrary text"), now, func() time.Time { return now })()
	if len(r.snapshot().Intervals) != 0 {
		t.Fatal("captured without active fixed phase")
	}
}

func TestOverlappingIntervalsAndOldCompletion(t *testing.T) {
	var r recorder
	start := time.Unix(1, 0)
	r.startAt(start)
	endA := r.beginAt(PhaseApplicationJoin, start, func() time.Time { return start.Add(24 * time.Second) })
	endB := r.beginAt(PhaseMacJoin, start.Add(2*time.Second), func() time.Time { return start.Add(22 * time.Second) })
	endB()
	endA()
	endA()
	s := r.snapshot()
	if len(s.Intervals) != 2 || s.Intervals[0].ElapsedMS != 24000 || s.Intervals[1].BeginMS != 2000 || s.Intervals[1].ElapsedMS != 20000 || !s.Intervals[0].Complete {
		t.Fatalf("overlap lost: %+v", s)
	}
	old := r.beginAt(PhaseUIStop, start, func() time.Time { return start })
	r.startAt(start.Add(time.Minute))
	old()
	if len(r.snapshot().Intervals) != 0 {
		t.Fatal("old interval crossed reset")
	}
}

func TestBoundedSnapshotCannotMutateRecorder(t *testing.T) {
	var r recorder
	now := time.Unix(1, 0)
	r.startAt(now)
	for i := 0; i < 40; i++ {
		r.beginAt(PhaseMacJoin, now, func() time.Time { return now })()
	}
	s := r.snapshot()
	if len(s.Intervals) != 32 || s.Omitted != 8 {
		t.Fatal("unbounded shutdown trace")
	}
	s.Intervals[0].Phase = "changed"
	if r.snapshot().Intervals[0].Phase != PhaseMacJoin {
		t.Fatal("snapshot aliases recorder")
	}
	data, err := json.Marshal(r.snapshot())
	if err != nil || len(data) > 4096 {
		t.Fatal("trace exceeds exit row allowance")
	}
}
