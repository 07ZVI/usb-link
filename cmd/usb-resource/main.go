// usb-resource is an external observer, never part of the product process tree.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"sort"
	"time"
)

type point struct{ X, Y float64 }
type metric struct {
	Mean float64 `json:"mean"`
	P95  float64 `json:"p95"`
	Max  float64 `json:"max"`
}

func describe(v []float64) *metric {
	if len(v) == 0 {
		return nil
	}
	a := append([]float64(nil), v...)
	sort.Float64s(a)
	var sum float64
	for _, x := range a {
		sum += x
	}
	return &metric{sum / float64(len(a)), a[int(math.Ceil(.95*float64(len(a))))-1], a[len(a)-1]}
}
func slope(v []point) *float64 {
	if len(v) < 2 {
		return nil
	}
	var sx, sy, sxx, sxy float64
	for _, p := range v {
		sx += p.X
		sy += p.Y
		sxx += p.X * p.X
		sxy += p.X * p.Y
	}
	n := float64(len(v))
	d := n*sxx - sx*sx
	if d <= 0 {
		return nil
	}
	r := (n*sxy - sx*sy) / d * 3600 / (1024 * 1024)
	return &r
}

type processSample struct {
	PID          uint32  `json:"pid"`
	ParentPID    uint32  `json:"parent_pid"`
	Name         string  `json:"name"`
	Created      uint64  `json:"creation_filetime"`
	CPUSeconds   float64 `json:"cpu_seconds_cumulative"`
	CPUPercent   float64 `json:"cpu_percent_one_core"`
	PrivateBytes uint64  `json:"private_bytes"`
	WorkingSet   uint64  `json:"working_set_bytes"`
	Handles      uint32  `json:"handles"`
	Threads      uint32  `json:"threads"`
	Exited       bool    `json:"exited"`
	Error        string  `json:"error,omitempty"`
}
type sample struct {
	ThreadSamples []threadSample  `json:"thread_samples,omitempty"`
	Elapsed       float64         `json:"elapsed_seconds"`
	Interval      float64         `json:"interval_seconds"`
	Processes     []processSample `json:"processes"`
	CPU           float64         `json:"known_cpu_percent_one_core"`
	Private       uint64          `json:"known_private_bytes"`
	Working       uint64          `json:"known_working_set_bytes"`
	Handles       uint64          `json:"known_handles"`
	Threads       uint64          `json:"known_threads"`
	Errors        []string        `json:"errors,omitempty"`
	Observer      processSample   `json:"observer_excluded_from_totals"`
	Switches      *float64        `json:"known_context_switches_per_second_not_wakeups"`
}
type threadSample struct {
	PID        uint32  `json:"pid"`
	TID        uint32  `json:"tid"`
	CPUPercent float64 `json:"cpu_percent_one_core"`
	Switches   float64 `json:"context_switches_per_second_not_wakeups"`
}
type series struct {
	CPU, Private, Working, Handles, Threads []float64
	Switches                                []float64
	CPUIntegral, Seconds                    float64
	Memory                                  []point
	WindowCPU                               []float64
	WindowIntegral, WindowSeconds           float64
}

func (s *series) add(r sample) {
	if r.Interval > 0 {
		s.CPUIntegral += r.CPU * r.Interval
		s.Seconds += r.Interval
		s.WindowIntegral += r.CPU * r.Interval
		s.WindowSeconds += r.Interval
		if s.WindowSeconds >= 60 {
			s.WindowCPU = append(s.WindowCPU, s.WindowIntegral/s.WindowSeconds)
			s.WindowIntegral = 0
			s.WindowSeconds = 0
		}
	}
	if r.Switches != nil {
		s.Switches = append(s.Switches, *r.Switches)
	}
	s.CPU = append(s.CPU, r.CPU)
	s.Private = append(s.Private, float64(r.Private))
	s.Working = append(s.Working, float64(r.Working))
	s.Handles = append(s.Handles, float64(r.Handles))
	s.Threads = append(s.Threads, float64(r.Threads))
	s.Memory = append(s.Memory, point{r.Elapsed, float64(r.Private)})
}
func (s *series) summary() any {
	cpu := describe(s.CPU)
	if cpu != nil && s.Seconds > 0 {
		cpu.Mean = s.CPUIntegral / s.Seconds
	}
	return struct {
		CPUWindow60           *metric  `json:"cpu_percent_one_core_window_60s"`
		CompleteWindows       int      `json:"complete_cpu_windows_60s"`
		TrailingWindowSeconds float64  `json:"trailing_cpu_window_seconds"`
		CPU                   *metric  `json:"cpu_percent_one_core"`
		PrivateBytes          *metric  `json:"private_bytes"`
		WorkingSetBytes       *metric  `json:"working_set_bytes"`
		Handles               *metric  `json:"handles"`
		Threads               *metric  `json:"threads"`
		Switches              *metric  `json:"known_context_switches_per_second_not_wakeups"`
		PrivateMiBPerHour     *float64 `json:"private_mib_per_hour"`
	}{describe(s.WindowCPU), len(s.WindowCPU), s.WindowSeconds, cpu, describe(s.Private), describe(s.Working), describe(s.Handles), describe(s.Threads), describe(s.Switches), slope(s.Memory)}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var threadCountersEnabled bool
var enumerationBackend = "uninitialized"

func run() error {
	duration := flag.Duration("duration", 30*time.Minute, "capture duration (1s..2h)")
	out := flag.String("output", "usb-resource", "new output prefix (.jsonl and .summary.json)")
	scenario := flag.String("scenario", "unspecified", "human scenario label; no automatic pass claim")
	root := flag.Uint("root-pid", 0, "optional exact product root PID, includes descendants")
	flag.BoolVar(&threadCountersEnabled, "thread-counters", false, "optional intrusive PDH thread profiling; disabled for resource baselines")
	flag.Parse()
	if *duration < time.Second || *duration > 2*time.Hour || *root > math.MaxUint32 {
		return fmt.Errorf("duration or PID out of bounds")
	}
	o, e := newObserver(uint32(*root))
	if e != nil {
		return e
	}
	defer o.close()
	f, e := os.OpenFile(*out+".jsonl", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	// Reserve the summary too, so an interrupted run cannot overwrite old evidence.
	summary, e := os.OpenFile(*out+".summary.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer summary.Close()
	encoder := json.NewEncoder(f)
	start := time.Now()
	last := start
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	defer signal.Stop(stop)
	base, e := o.capture(0, 0)
	if e != nil {
		return e
	}
	if e = encoder.Encode(base); e != nil {
		return e
	}
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	var data series
	var observerData series
	missing := 0
	count := 0
	cancelled := false
loop:
	for {
		select {
		case <-stop:
			cancelled = true
			break loop
		case <-timer.C:
			now := time.Now()
			r, e := o.capture(now.Sub(start).Seconds(), now.Sub(last).Seconds())
			last = now
			if e != nil {
				return e
			}
			if e = encoder.Encode(r); e != nil {
				return e
			}
			count++
			if len(r.Errors) > 0 {
				missing++
			}
			data.add(r)
			p := r.Observer
			observerData.add(sample{Elapsed: r.Elapsed, Interval: r.Interval, CPU: p.CPUPercent, Private: p.PrivateBytes, Working: p.WorkingSet, Handles: uint64(p.Handles), Threads: uint64(p.Threads)})
			if now.Sub(start) >= *duration {
				break loop
			}
		}
	}
	if e = f.Sync(); e != nil {
		return e
	}
	report := map[string]any{"schema": 1, "scenario": *scenario, "started_utc": start.UTC().Format(time.RFC3339Nano), "requested_seconds": duration.Seconds(), "observed_seconds": time.Since(start).Seconds(), "interrupted": cancelled, "samples": count, "samples_with_errors": missing, "known_product_totals": data.summary(), "observer_excluded": observerData.summary(), "process_lifetimes": o.lifetimes(), "observed_starts": o.starts(), "coverage": map[string]any{"process_enumeration": enumerationBackend, "cpu": "p95 acceptance uses complete >=60s windows; 1s p95 is diagnostic only; GetProcessTimes; retained handles include exit CPU; PID plus creation time identity", "memory": "GetProcessMemoryInfo; live samples only", "child_starts": "snapshot lower bound; processes wholly between 1s snapshots can be missed", "context_switches": schedulerCoverage(), "wakeups": "unmeasured; requires a separate scheduler trace", "zero_child_starts_gate": "NOT_EVALUATED_without_process_lifecycle_trace", "names_only": true}, "pass": nil}
	if e = json.NewEncoder(summary).Encode(report); e != nil {
		return e
	}
	return summary.Sync()
}

func schedulerCoverage() string {
	if threadCountersEnabled {
		return "PDH English Thread counters; intrusive short diagnostic; not wakeups"
	}
	return "unmeasured; PDH disabled to limit observer perturbation"
}
