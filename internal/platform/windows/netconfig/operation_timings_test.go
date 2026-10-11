package netconfig

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNetworkTimingsBoundedAndConcurrent(t *testing.T) {
	before := NativeOperationTimingsSnapshot()
	baseline := NativeOperationTiming{}
	for _, row := range before {
		if row.Operation == "shared_host_firewall" {
			baseline = row
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(failed bool) {
			defer wg.Done()
			finish := beginNetworkTiming("shared_host_firewall")
			var err error
			if failed {
				err = errors.New("provider secret must never be exported")
			}
			finish(err)
			finish(err) // A duplicate completion cannot corrupt counters.
		}(i%2 == 0)
	}
	wg.Wait()
	beginNetworkTiming("user-input-not-a-fixed-operation")(nil)
	rows := NativeOperationTimingsSnapshot()
	if len(rows) > len(networkTimingNames) {
		t.Fatal("unbounded operation names")
	}
	found := false
	for _, row := range rows {
		if row.Operation == "user-input-not-a-fixed-operation" {
			t.Fatal("unknown name exported")
		}
		if row.Operation != "shared_host_firewall" {
			continue
		}
		found = true
		if row.Count != baseline.Count+32 || row.Failures != baseline.Failures+16 || row.InFlight != 0 || row.CumulativeMS < baseline.CumulativeMS || row.LastMS < 0 {
			t.Fatal(row)
		}
		start, e1 := time.Parse(time.RFC3339Nano, row.LastBeginUTC)
		end, e2 := time.Parse(time.RFC3339Nano, row.LastEndUTC)
		if e1 != nil || e2 != nil || end.Before(start) {
			t.Fatal("invalid completed span", row)
		}
	}
	if !found {
		t.Fatal("missing observation")
	}
	rows[0].Operation = "modified snapshot"
	for _, row := range NativeOperationTimingsSnapshot() {
		if row.Operation == "modified snapshot" {
			t.Fatal("snapshot aliases storage")
		}
	}
}
