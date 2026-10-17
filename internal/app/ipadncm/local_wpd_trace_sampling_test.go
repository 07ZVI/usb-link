//go:build usblink_local_remote

package ipadncm

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestWPDCriticalSamplingSurvivesUSBNoise(t *testing.T) {
	var gate wpdTraceSamplingGate
	var sample localWPDTraceSample
	reads := 0
	deliver := func(h localWPDTraceSchema) {
		if !gate.admit(100, &sample, h) {
			return
		}
		reads++
		h.Stage = "metadata_read_failed"
		sample.recordDecode(h)
	}
	for i := 0; i < 100; i++ {
		deliver(localWPDTraceSchema{Provider: "usb", EventID: 102})
	}
	for i := 0; i < 6; i++ {
		deliver(localWPDTraceSchema{Provider: "mtp", EventID: 2000})
		deliver(localWPDTraceSchema{Provider: "mtp", EventID: 2001})
	}
	deliver(localWPDTraceSchema{Provider: "mtp", EventID: 2001})
	if reads != 16 || sample.DecodeCounts.Attempted != 16 || sample.SampledOut != 97 || sample.HeaderOnlyEvents != 97 {
		t.Fatal(reads, sample)
	}
	if sample.CriticalSampling != (wpdCriticalSampling{{Seen: 6, Parsed: 6}, {Seen: 7, Parsed: 6, Skipped: 1}}) {
		t.Fatal(sample.CriticalSampling)
	}
	// Parsed means admitted for inspection, even when metadata retrieval fails.
	if sample.Decoded != 0 || sample.DecodeCounts.MetadataFailed != 16 {
		t.Fatal(sample.DecodeCounts)
	}
	before := sample
	if !gate.admit(101, &sample, localWPDTraceSchema{Provider: "mtp", EventID: 2001}) || before.CriticalSampling[1].Seen != 7 {
		t.Fatal("new second or snapshot isolation failed")
	}
}

func TestWPDCriticalSamplingIdentityAndSharedCap(t *testing.T) {
	for _, noise := range []localWPDTraceSchema{
		{Provider: "api", EventID: 2000}, {Provider: "usb", EventID: 2001},
		{Provider: "", EventID: 2001}, {Provider: "mtp", EventID: 2004},
		{Provider: "mtp", EventID: 2001, Version: 1},
	} {
		var gate wpdTraceSamplingGate
		var s localWPDTraceSample
		for i := 0; i < 20; i++ {
			if got := gate.admit(100, &s, noise); got != (i < 4) {
				t.Fatal(noise, i, got)
			}
		}
		if s.CriticalSampling != (wpdCriticalSampling{}) {
			t.Fatal("unverified header counted as critical", noise)
		}
		for i := 0; i < 13; i++ {
			if got := gate.admit(100, &s, localWPDTraceSchema{Provider: "mtp", EventID: 2001}); got != (i < 12) {
				t.Fatal("shared cap", i, got)
			}
		}
	}
	var gate wpdTraceSamplingGate
	var s localWPDTraceSample
	for i := 0; i < 17; i++ {
		if got := gate.admit(100, &s, localWPDTraceSchema{Provider: "mtp", EventID: 2000}); got != (i < 16) {
			t.Fatal("critical-only cap", i, got)
		}
	}
	if gate.admit(100, &s, localWPDTraceSchema{Provider: "usb"}) {
		t.Fatal("general events exceeded shared cap")
	}
	if !gate.admit(101, &s, localWPDTraceSchema{Provider: "usb"}) || gate.count != 1 || gate.general != 1 {
		t.Fatal("boundary did not reset both budgets")
	}
}

func TestWPDCriticalSamplingSerializedCallbacksAndSaturation(t *testing.T) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var gate wpdTraceSamplingGate
	var s localWPDTraceSample
	reads := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mu.Lock() // Same lock boundary as the native callback.
			defer mu.Unlock()
			if gate.admit(100, &s, localWPDTraceSchema{Provider: "mtp", EventID: 2000 + uint16(i%2)}) {
				reads++
			}
		}(i)
	}
	wg.Wait()
	if reads != 16 || s.SampledOut != 84 {
		t.Fatal(reads, s.SampledOut)
	}
	for _, c := range s.CriticalSampling {
		if c.Seen != 50 || c.Seen != c.Parsed+c.Skipped {
			t.Fatal(c)
		}
	}
	c := wpdCriticalEventCounts{Seen: ^uint64(0) - 1, Parsed: ^uint64(0) - 2, Skipped: 1}
	c.record(false)
	before := c
	c.record(true)
	if c != before || c.Seen != c.Parsed+c.Skipped {
		t.Fatal("saturation lost accounting", c)
	}
	b, err := json.Marshal(localWPDTraceStatus{localWPDTraceSample: s})
	var wire struct {
		Sampling struct {
			Unit, Scope string
			Parsed      string `json:"parsed_semantics"`
		} `json:"critical_sampling"`
	}
	if err != nil || len(b) > 4096 || json.Unmarshal(b, &wire) != nil || wire.Sampling.Unit != "etw_events" || wire.Sampling.Scope != "system_unattributed" || wire.Sampling.Parsed != "admitted_not_success" {
		t.Fatal(string(b), err)
	}
}
