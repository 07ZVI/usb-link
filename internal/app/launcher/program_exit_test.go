package launcher

import (
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const exitID1 = "11111111111111111111111111111111"
const exitID2 = "22222222222222222222222222222222"

var exitOwner = programExitOwner{SID: "owner", Session: 1, PID: 2, Creation: 3}

func waitExit(t *testing.T, e *coreProgramExit, phase string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e.snapshot().Phase == phase {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("wanted %s; got %+v", phase, e.snapshot())
}
func TestProgramExitJoinsBeforeRestoreAndRetries(t *testing.T) {
	joined := make(chan struct{})
	var stops, restores atomic.Int32
	e := newCoreProgramExit(func() { stops.Add(1); <-joined }, func() error {
		if restores.Add(1) == 1 {
			return errors.New("private native error")
		}
		return nil
	})
	if err := e.begin(exitID1, exitOwner); err != nil {
		t.Fatal(err)
	}
	if err := e.begin(exitID1, exitOwner); err != nil {
		t.Fatal("duplicate should be idempotent", err)
	}
	if _, err := e.prepareCommit(exitID1, exitOwner); err == nil {
		t.Fatal("commit before restoration")
	}
	if restores.Load() != 0 {
		t.Fatal("restored before application join")
	}
	close(joined)
	waitExit(t, e, "failed")
	if e.snapshot().Error != "CORE_EXIT_RECOVERY_PENDING" {
		t.Fatal("unsafe error disclosure")
	}
	if err := e.begin(exitID2, exitOwner); err != nil {
		t.Fatal(err)
	}
	waitExit(t, e, "ready")
	if stops.Load() != 1 || restores.Load() != 2 {
		t.Fatal("stop once; restore each retry")
	}
	after, err := e.prepareCommit(exitID2, exitOwner)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.committed:
		t.Fatal("stopped before reply acknowledgement")
	default:
	}
	after()
	after()
	select {
	case <-e.committed:
	default:
		t.Fatal("did not exit after acknowledgement")
	}
}
func TestProgramExitOwnerTakeoverOnlyAfterQuiescence(t *testing.T) {
	gate := make(chan struct{})
	e := newCoreProgramExit(func() { <-gate }, func() error { return nil })
	if err := e.begin(exitID1, exitOwner); err != nil {
		t.Fatal(err)
	}
	successor := exitOwner
	successor.PID++
	successor.Creation++
	if e.begin(exitID2, successor) == nil {
		t.Fatal("takeover while stopping")
	}
	close(gate)
	waitExit(t, e, "ready")
	stale, _ := e.prepareCommit(exitID1, exitOwner)
	for _, other := range []programExitOwner{{SID: "foreign", Session: 1, PID: 4, Creation: 5}, {SID: "owner", Session: 2, PID: 4, Creation: 5}} {
		if e.begin(exitID2, other) == nil {
			t.Fatal("foreign takeover")
		}
	}
	if e.begin(exitID1, successor) == nil {
		t.Fatal("new process must rotate request id")
	}
	if err := e.begin(exitID2, successor); err != nil {
		t.Fatal(err)
	}
	waitExit(t, e, "ready")
	stale()
	select {
	case <-e.committed:
		t.Fatal("stale acknowledgement committed new owner")
	default:
	}
	if _, err := e.prepareCommit(exitID1, exitOwner); err == nil {
		t.Fatal("old owner can commit")
	}
	after, err := e.prepareCommit(exitID2, successor)
	if err != nil {
		t.Fatal(err)
	}
	after()
}
func TestProgramExitSnapshotNeverReusesHealthyConnections(t *testing.T) {
	gate := make(chan struct{})
	e := newCoreProgramExit(func() { <-gate }, func() error { return nil })
	current := json.RawMessage(`{"desktop":{"event":"status","version":"test","connected":true,"devices":[{"device":"iPad","connected":true}]},"connections":{"iPad":{"connected":true}},"events":[{"event":"gateway-request"}]}`)
	e.display(current, nil, "test")
	if err := e.begin(exitID1, exitOwner); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Desktop struct {
			Connected bool
			Devices   []any
			Version   string
			Exit      programExitStatus `json:"program_exit"`
		}
		Connections map[string]any
		Events      []any
	}
	if err := json.Unmarshal(e.display(nil, map[string]any{"phase": "restoring"}, "test"), &out); err != nil {
		t.Fatal(err)
	}
	if out.Desktop.Connected || len(out.Desktop.Devices) != 0 || len(out.Connections) != 2 || len(out.Events) != 0 || out.Desktop.Version != "test" || out.Desktop.Exit.Phase != "stopping_connections" {
		t.Fatalf("stale healthy snapshot %+v", out)
	}
	close(gate)
	waitExit(t, e, "ready")
}

func TestProgramExitFailedRecoveryCanMoveToReopenedOwnerUI(t *testing.T) {
	var tries atomic.Int32
	var mu sync.Mutex
	var stages []string
	e := newCoreProgramExit(func() {}, func() error {
		if tries.Add(1) == 1 {
			return errors.New("pending")
		}
		return nil
	})
	e.record = func(stage, id string) {
		if id != exitID1 && id != exitID2 {
			t.Error("unbounded request id")
		}
		mu.Lock()
		stages = append(stages, stage)
		mu.Unlock()
	}
	if err := e.begin(exitID1, exitOwner); err != nil {
		t.Fatal(err)
	}
	waitExit(t, e, "failed")
	successor := exitOwner
	successor.PID++
	successor.Creation++
	if err := e.begin(exitID2, successor); err != nil {
		t.Fatal(err)
	}
	waitExit(t, e, "ready")
	after, err := e.prepareCommit(exitID2, successor)
	if err != nil {
		t.Fatal(err)
	}
	after()
	mu.Lock()
	defer mu.Unlock()
	want := []string{"APPLICATION_JOINED", "RESTORE_FAILED", "APPLICATION_JOINED", "RESTORE_READY", "COMMIT_ACKNOWLEDGED"}
	if !reflect.DeepEqual(stages, want) {
		t.Fatalf("lifecycle evidence: %v", stages)
	}
}
