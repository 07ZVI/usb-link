package ipadncm

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNetworkOnlyPhaseCaptureIsDefaultOffSingleAttemptAndBounded(t *testing.T) {
	c := new(networkOnlyPhaseCapture)
	now := time.Unix(1700000000, 0)
	if _, ok := c.begin(1, now); ok {
		t.Fatal("default off started observation")
	}
	c.set(true, now)
	if _, ok := c.begin(0, now); ok {
		t.Fatal("unbound attempt accepted")
	}
	budget, ok := c.begin(7, now)
	if !ok || budget != 2*time.Second {
		t.Fatal("initial budget invalid")
	}
	c.set(true, now.Add(time.Second))
	if _, ok := c.begin(7, now); ok {
		t.Fatal("concurrent observation accepted")
	}
	c.finish(1200 * time.Millisecond)
	if _, ok := c.begin(8, now); ok {
		t.Fatal("different attempt imported")
	}
	budget, ok = c.begin(7, now)
	if !ok || budget != 800*time.Millisecond {
		t.Fatal("budget reset instead of accumulated")
	}
	c.finish(900 * time.Millisecond)
	if c.active(now) {
		t.Fatal("exhausted capture still active")
	}
	c.set(true, now)
	if c.active(now.Add(120 * time.Second)) {
		t.Fatal("expired capture still active")
	}
	c.set(false, now)
	if c.active(now) {
		t.Fatal("explicit OFF ignored")
	}
}

func TestNetworkOnlyPhaseCaptureOffDuringObservationCannotReenable(t *testing.T) {
	c := new(networkOnlyPhaseCapture)
	now := time.Now()
	c.set(true, now)
	if _, ok := c.begin(3, now); !ok {
		t.Fatal("cannot start capture")
	}
	c.set(false, now)
	c.finish(time.Millisecond)
	if c.state(now).Enabled {
		t.Fatal("completion re-enabled capture")
	}
}

func TestNetworkOnlyPhaseUnknownInventoryIsNotEmpty(t *testing.T) {
	d := NetworkOnlyPhaseDiagnostic{}
	d.setPresentInventory(0, false)
	if d.PresentCount != nil || d.PresentComplete || d.PresentEmpty {
		t.Fatal("unreadable inventory was represented as complete empty")
	}
	b, err := json.Marshal(d)
	if err != nil || !strings.Contains(string(b), `"present_portable_count":null`) {
		t.Fatalf("unknown count lost on wire: %s %v", b, err)
	}
	d.setPresentInventory(0, true)
	if d.PresentCount == nil || *d.PresentCount != 0 || !d.PresentComplete || !d.PresentEmpty {
		t.Fatal("complete empty observation was lost")
	}
	d.setPresentInventory(2, true)
	if *d.PresentCount != 2 || d.PresentEmpty {
		t.Fatal("nonempty inventory misclassified")
	}
	d.setPresentInventory(2, false)
	if d.PresentCount != nil || d.PresentEmpty || d.PresentComplete {
		t.Fatal("a later incomplete observation retained prior proof")
	}
}

func TestNetworkOnlyPhaseHistoryBoundsAndImmutableSnapshots(t *testing.T) {
	h := new(networkOnlyPhaseHistory)
	n := 19
	d := NetworkOnlyPhaseDiagnostic{PresentCount: &n, PresentNodes: make([]NetworkOnlyPhaseNode, 19), OwnedNodes: make([]NetworkOnlyPhaseNode, 18)}
	d.PresentNodes[0].Digest = "digest-before"
	d.PresentNodes[0].Native.Problem = 22
	for i := 0; i < 40; i++ {
		d.Attempt = uint64(i)
		h.record(d)
	}
	n = 99
	d.PresentNodes[0].Digest = "changed-input"
	d.PresentNodes[0].Native.Problem = 0
	x := h.snapshot()
	if len(x) != 32 || x[0].Attempt != 8 || len(x[0].PresentNodes) != 16 || len(x[0].OwnedNodes) != 16 || x[0].PresentOmitted != 3 || x[0].OwnedOmitted != 2 {
		t.Fatalf("history/query bounds lost: %+v", x[0])
	}
	if *x[0].PresentCount != 19 || x[0].PresentNodes[0].Digest != "digest-before" || x[0].PresentNodes[0].Native.Problem != 22 {
		t.Fatal("input mutation changed retained evidence")
	}
	*x[0].PresentCount = 100
	x[0].PresentNodes[0].Digest = "changed-output"
	y := h.snapshot()
	if *y[0].PresentCount != 19 || y[0].PresentNodes[0].Digest != "digest-before" {
		t.Fatal("snapshot mutation changed retained evidence")
	}
}

func TestNetworkOnlyPhaseHistoryConcurrentReaders(t *testing.T) {
	h := new(networkOnlyPhaseHistory)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				h.record(NetworkOnlyPhaseDiagnostic{Attempt: uint64(j)})
				_ = h.snapshot()
			}
		}()
	}
	wg.Wait()
	if len(h.snapshot()) != 32 {
		t.Fatal("concurrent history is unbounded")
	}
}

func TestNetworkOnlyPhaseNativeCollectorCannotChangeDeviceOrService(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "network_only_phase_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"Start": true, "Stop": true, "Control": true, "UpdateConfig": true, "SetupDiSetDeviceRegistryProperty": true, "SetDeviceRegistryProperty": true, "saveNetworkOnlyReceipt": true, "setPortableDisabled": true, "EnsureNetworkOnly": true, "applyNetworkOnlyService": true, "CreateFile": true, "WriteFile": true}
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fn := c.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if forbidden[name] {
			t.Errorf("diagnostic collector calls mutating helper %s", name)
		}
		return true
	})
}
