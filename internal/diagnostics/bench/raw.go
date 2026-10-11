package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime/pprof"
	"runtime/trace"
	"suhang/usbnet/internal/diagnostics/rawusb"
	"sync"
)

type RawRunner func(context.Context, string, int, string, func(int) error) (rawusb.Result, error)

var rawMu sync.Mutex
var rawRunner RawRunner

func SetRawRunner(f RawRunner) { rawMu.Lock(); rawRunner = f; rawMu.Unlock() }
func rawPerformance(ctx context.Context, conn io.Writer, kind string, seconds int, nonce string, out io.Writer) error {
	rawMu.Lock()
	run := rawRunner
	rawMu.Unlock()
	if run == nil {
		return fmt.Errorf("raw USB diagnostics unavailable")
	}
	_, profile, _, _ := rawusb.Command(kind)
	b := &boundedProfile{limit: 48 << 20}
	var stop func()
	if profile == "CPU" {
		if err := pprof.StartCPUProfile(b); err != nil {
			return err
		}
		stop = pprof.StopCPUProfile
	}
	if profile == "TRACE" {
		if err := trace.Start(b); err != nil {
			return err
		}
		stop = trace.Stop
	}
	// Directional capture lasts exactly for this bounded raw experiment.
	r, err := run(ctx, kind, seconds, nonce, func(ipLength int) error { _, e := fmt.Fprintf(conn, "READY %s %d\n", nonce, ipLength); return e })
	if stop != nil {
		stop()
	}
	if err != nil {
		return err
	}
	p, err := b.result()
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(rawusb.Capture{Raw: r, ProfileKind: profile, Profile: p})
}
