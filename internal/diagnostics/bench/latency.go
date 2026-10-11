package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"suhang/usbnet/internal/diagnostics/latencyprobe"
	"sync"
)

var latencyMu sync.RWMutex
var latencyRunner func(context.Context, string, int, string, string) (any, error)

// Published under a lock when the bridge transport becomes ready.
func SetLatencyRunner(f func(context.Context, string, int, string, string) (any, error)) {
	latencyMu.Lock()
	latencyRunner = f
	latencyMu.Unlock()
}
func handleLatency(ctx context.Context, conn io.ReadWriter, fields []string) error {
	if len(fields) != 5 {
		return fmt.Errorf("invalid latency request")
	}
	n, e := strconv.Atoi(fields[2])
	if e != nil {
		return e
	}
	if e = latencyprobe.Validate(fields[1], n, fields[3], fields[4]); e != nil {
		return e
	}
	latencyMu.RLock()
	runner := latencyRunner
	latencyMu.RUnlock()
	if runner == nil {
		return fmt.Errorf("latency diagnostics unavailable")
	}
	if !captureMu.TryLock() {
		return fmt.Errorf("capture already active")
	}
	defer captureMu.Unlock()
	v, e := runner(ctx, fields[1], n, fields[3], fields[4])
	if e != nil {
		return e
	}
	return json.NewEncoder(conn).Encode(v)
}
