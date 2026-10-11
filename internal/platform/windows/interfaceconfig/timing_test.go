package interfaceconfig

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestObservationsBoundedFixedScopeAndConcurrentSnapshots(t *testing.T) {
	timings.Lock()
	old := timings.values
	timings.values = nil
	timings.Unlock()
	defer func() { timings.Lock(); timings.values = old; timings.Unlock() }()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recordTiming("mac", "persistent_reuse", time.Now().Add(-time.Millisecond), errors.New("private local path must never export"), false)
			_ = ObservationsSnapshot()
		}()
	}
	wg.Wait()
	recordTiming("ipad", "dad_apply", time.Now(), nil, true)
	recordTiming("arbitrary role", "dad_apply", time.Now(), nil, false)
	recordTiming("host", "arbitrary path", time.Now(), nil, false)
	got := ObservationsSnapshot()
	if len(got) != 2 || got[0].Role != "mac" || got[0].Kind != "persistent_reuse" || got[0].Calls != 20 || got[0].Failures != 20 || got[0].DurationMS < 20 || got[1].Disabled != 1 {
		t.Fatal(got)
	}
	got[0].Calls = 999
	if ObservationsSnapshot()[0].Calls != 20 {
		t.Fatal("mutable shared snapshot")
	}
}
