package uistartup

import (
	"strings"
	"sync"
	"testing"
)

func TestInvalidRecordsNeverEnterHistory(t *testing.T) {
	good := Timing{strings.Repeat("a", 32), "renderer-opened", 20}
	if !Valid(good) {
		t.Fatal("known stage rejected")
	}
	for _, bad := range []Timing{{good.Request, "network-ready", 20}, {good.Request, "renderer-opened", 0}, {good.Request, "renderer-opened", 600_000_001}, {"foreign", good.Stage, 20}, {strings.Repeat("G", 32), good.Stage, 20}} {
		if Valid(bad) || Record([]Timing{good, bad}, 11, 123) {
			t.Fatal("invalid record accepted", bad)
		}
	}
	if Record([]Timing{good}, 0, 123) || Record([]Timing{good}, 11, 0) || Record(make([]Timing, 33), 11, 123) {
		t.Fatal("unbound/oversized batch accepted")
	}
}
func TestBoundedQueueConcurrentAndFailureRestore(t *testing.T) {
	var q Queue
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 20 {
				q.Add(Timing{strings.Repeat("b", 32), "payload-verified", 15})
			}
		}()
	}
	workers.Wait()
	batch := q.Take()
	if len(batch) != 32 || len(q.Take()) != 0 {
		t.Fatal("queue unbounded/not drained")
	}
	q.Restore(batch)
	if len(q.Take()) != 32 {
		t.Fatal("failed IPC loses pending observations")
	}
}

func TestRendererMarkersCannotBecomeActionsOrReadiness(t *testing.T) {
	for _, stage := range []string{"renderer-main", "renderer-app-initialize", "renderer-theme-ready", "renderer-dashboard-create", "renderer-dashboard-ready", "renderer-first-managed-draw"} {
		if !RendererStage(stage) || !Valid(Timing{strings.Repeat("e", 32), stage, 100}) {
			t.Fatal("renderer phase rejected", stage)
		}
	}
	for _, stage := range []string{"ready", "stop", "startup-on", "network-ready", "renderer-opened", "existing-renderer-show-queued", "renderer-stage", "Renderer-main", "renderer-first-managed-draw\n", ""} {
		if RendererStage(stage) {
			t.Fatal("non-marker accepted", stage)
		}
	}
}

func TestLoginSubphasesRemainDisplayOnly(t *testing.T) {
	for _, stage := range []string{"login-self-source-pinned", "login-service-start-verified"} {
		if !Valid(Timing{strings.Repeat("e", 32), stage, 100}) || RendererStage(stage) {
			t.Fatal("login timing confused with renderer marker", stage)
		}
	}
}
