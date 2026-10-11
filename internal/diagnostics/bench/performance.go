package bench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
	"runtime/metrics"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"suhang/usbnet/internal/diagnostics/latencyprobe"
	"suhang/usbnet/internal/diagnostics/rawusb"
	"sync"
	"sync/atomic"
	"time"
)

const PerfProtocol = "SUHANG-USB-PERF/1"
const profileLimit = 64 << 20

// Only fixed captures and two temporary GC presets are accepted, on the
// existing USB-peer-only benchmark listener. No paths, code or general pprof
// endpoint are accepted. Profiling is idle unless explicitly requested.
var memorySnapshot func() any
var captureMu sync.Mutex
var gcMu sync.Mutex
var gcTimer *time.Timer
var trimBuffers func()

func SetBufferTrim(f func()) { gcMu.Lock(); trimBuffers = f; gcMu.Unlock() }

var gcGeneration uint64
var gcBasePercent, gcBaseLimit = initialGC()
var gcPreset = "DEFAULT"
var reuseBuffers atomic.Bool
var cachedWinUSB atomic.Bool

const DefaultBuffers = true

func init() {
	reuseBuffers.Store(DefaultBuffers)
	cachedWinUSB.Store(true)
}
func CachedWinUSB() bool { return cachedWinUSB.Load() }
func ReuseBuffers() bool { return reuseBuffers.Load() }

func initialGC() (int, int64) {
	s := []metrics.Sample{{Name: "/gc/gogc:percent"}, {Name: "/gc/gomemlimit:bytes"}}
	metrics.Read(s)
	return int(s[0].Value.Uint64()), int64(s[1].Value.Uint64())
}
func GCSettings() (string, int, int64) {
	gcMu.Lock()
	defer gcMu.Unlock()
	if gcPreset == "GC800" || gcPreset == "BUFFERS800" {
		return gcPreset, 800, 256 << 20
	}
	return gcPreset, gcBasePercent, gcBaseLimit
}
func RestoreGC() {
	gcMu.Lock()
	defer gcMu.Unlock()
	gcGeneration++
	if gcTimer != nil {
		gcTimer.Stop()
		gcTimer = nil
	}
	debug.SetGCPercent(gcBasePercent)
	debug.SetMemoryLimit(gcBaseLimit)
	gcPreset = "DEFAULT"
	reuseBuffers.Store(DefaultBuffers)
	cachedWinUSB.Store(true)
}
func setGC(kind string) {
	gcMu.Lock()
	defer gcMu.Unlock()
	gcGeneration++
	if gcTimer != nil {
		gcTimer.Stop()
		gcTimer = nil
	}
	debug.SetGCPercent(gcBasePercent)
	debug.SetMemoryLimit(gcBaseLimit)
	gcPreset = kind
	cachedWinUSB.Store(kind != "USBORIGINAL")
	reuseBuffers.Store(kind == "USBCACHED" || kind == "USBORIGINAL" || kind == "BUFFERS" || kind == "BUFFERS800" || (kind == "DEFAULT" || kind == "GC100") && DefaultBuffers)
	if !reuseBuffers.Load() && trimBuffers != nil {
		trimBuffers()
	}
	if kind == "GC800" || kind == "BUFFERS800" {
		debug.SetMemoryLimit(256 << 20)
		debug.SetGCPercent(800)
	}
	if kind == "DEFAULT" || kind == "GC100" {
		return
	}
	generation := gcGeneration
	gcTimer = time.AfterFunc(time.Minute, func() {
		gcMu.Lock()
		defer gcMu.Unlock()
		if gcGeneration != generation {
			return
		}
		debug.SetGCPercent(gcBasePercent)
		debug.SetMemoryLimit(gcBaseLimit)
		gcPreset = "DEFAULT"
		reuseBuffers.Store(DefaultBuffers)
		cachedWinUSB.Store(true)
		gcTimer = nil
	})
}

type boundedProfile struct {
	mu    sync.Mutex
	b     bytes.Buffer
	limit int
	err   error
}

func (b *boundedProfile) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return 0, b.err
	}
	n := min(len(p), b.limit-b.b.Len())
	if n > 0 {
		b.b.Write(p[:n])
	}
	if n != len(p) {
		b.err = fmt.Errorf("profile exceeds fixed byte limit")
		return n, b.err
	}
	return n, nil
}
func (b *boundedProfile) result() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Bytes(), b.err
}

func handlePerformance(ctx context.Context, conn io.ReadWriter, fields []string) error {
	if len(fields) != 4 || fields[0] != PerfProtocol {
		return fmt.Errorf("invalid performance request")
	}
	seconds, err := strconv.Atoi(fields[2])
	if err != nil {
		return err
	}
	kind := fields[1]
	if err = ValidatePerformance(kind, seconds, fields[3]); err != nil {
		return err
	}
	if !captureMu.TryLock() {
		return fmt.Errorf("capture already active")
	}
	defer captureMu.Unlock()
	b := &boundedProfile{limit: profileLimit}
	if _, _, _, raw := rawusb.Command(kind); raw {
		if latencyprobe.Running() {
			return fmt.Errorf("latency probe already active")
		}
		if err = rawPerformance(ctx, conn, kind, seconds, fields[3], b); err != nil {
			return err
		}
	} else if kind == "WAITSTATE" {
		json.NewEncoder(b).Encode(WaitDiagnostics())
	} else if kind == "WAITBASELINE" || kind == "WAITDEFAULT" || kind == "WAITEVENTS" || kind == "WAITEVENTSLONG" || kind == "WAITEVENTSHOUR" {
		experimentSeconds := 0
		if kind == "WAITEVENTS" || kind == "WAITEVENTSLONG" || kind == "WAITEVENTSHOUR" {
			experimentSeconds = seconds
		}
		SetEventWaitExperiment(experimentSeconds)
		json.NewEncoder(b).Encode(map[string]any{"event_waits_enabled": EventWaits(), "temporary_seconds": experimentSeconds})
	} else if kind == "USBCACHED" || kind == "USBORIGINAL" || kind == "GC100" || kind == "GC800" || kind == "BASELINE" || kind == "BUFFERS" || kind == "BUFFERS800" || kind == "DEFAULT" {
		setGC(kind)
		preset, percent, limit := GCSettings()
		json.NewEncoder(b).Encode(map[string]any{"preset": preset, "gc_percent": percent, "memory_limit": limit, "temporary_seconds": 60, "buffers_reused": ReuseBuffers(), "winusb_cached": CachedWinUSB()})
	} else {
		var stop func()
		switch kind {
		case "CPU":
			err = pprof.StartCPUProfile(b)
			stop = pprof.StopCPUProfile
		case "TRACE":
			err = trace.Start(b)
			stop = trace.Stop
		case "ALLOCS":
			err = pprof.Lookup("allocs").WriteTo(b, 0)
		case "HEAP":
			err = pprof.Lookup("heap").WriteTo(b, 0)
		case "FREEMEMORY":
			if memorySnapshot == nil {
				return fmt.Errorf("native memory diagnostics unavailable")
			}
			before := memorySnapshot()
			debug.FreeOSMemory()
			err = json.NewEncoder(b).Encode(map[string]any{"before": before, "after": memorySnapshot(), "diagnostic_only": true, "policy_changed": false})
		case "MEMORY":
			if memorySnapshot == nil {
				return fmt.Errorf("native memory diagnostics unavailable")
			}
			err = json.NewEncoder(b).Encode(memorySnapshot())
		}
		if err != nil {
			return err
		}
		if stop != nil {
			// Stop is always called, including disconnect/cancellation, before reading
			// the buffer or letting another capture start.
			if _, err = fmt.Fprintf(conn, "READY %s\n", fields[3]); err != nil {
				stop()
				return err
			}
			timer := time.NewTimer(time.Duration(seconds) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				stop()
				return ctx.Err()
			case <-timer.C:
			}
			stop()
		}
	}
	payload, err := b.result()
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	if _, err = fmt.Fprintf(conn, "DONE %s %d %s\n", fields[3], len(payload), hex.EncodeToString(sum[:])); err != nil {
		return err
	}
	_, err = conn.Write(payload)
	return err
}

func ValidatePerformance(kind string, seconds int, nonce string) error {
	if !noncePattern.MatchString(nonce) {
		return fmt.Errorf("invalid capture nonce")
	}
	if _, profile, _, raw := rawusb.Command(kind); raw {
		minSeconds, maxSeconds := 5, 15
		if profile == "TRACE" {
			minSeconds, maxSeconds = 1, 5
		}
		if seconds < minSeconds || seconds > maxSeconds {
			return fmt.Errorf("raw duration out of bounds")
		}
		return nil
	}
	switch kind {
	case "WAITEVENTSHOUR":
		if seconds != 3900 {
			return fmt.Errorf("fixed hour wait experiment lease required")
		}
	case "WAITEVENTSLONG":
		if seconds != 900 {
			return fmt.Errorf("fixed long wait experiment lease required")
		}
	case "WAITBASELINE", "WAITEVENTS":
		if seconds != 120 {
			return fmt.Errorf("fixed wait baseline duration required")
		}
	case "WAITSTATE", "WAITDEFAULT":
		if seconds != 0 {
			return fmt.Errorf("unexpected duration")
		}
	case "CPU":
		if seconds < 1 || seconds > 30 {
			return fmt.Errorf("CPU duration out of bounds")
		}
	case "TRACE":
		if seconds < 1 || seconds > 5 {
			return fmt.Errorf("trace duration out of bounds")
		}
	case "FREEMEMORY", "MEMORY", "ALLOCS", "HEAP", "USBCACHED", "USBORIGINAL", "GC100", "GC800", "BASELINE", "BUFFERS", "BUFFERS800", "DEFAULT":
		if seconds != 0 {
			return fmt.Errorf("unexpected duration")
		}
	default:
		return fmt.Errorf("unknown fixed capture")
	}
	return nil
}

// CaptureFixed writes the existing bounded profile protocol to an authenticated caller.
func CaptureFixed(ctx context.Context, out io.ReadWriter, kind string, seconds int, nonce string) error {
	return handlePerformance(ctx, out, []string{PerfProtocol, kind, strconv.Itoa(seconds), nonce})
}
