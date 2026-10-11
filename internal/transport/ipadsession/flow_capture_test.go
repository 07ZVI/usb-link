package ipadsession

import (
	"testing"
	"time"
)

func TestFlowCaptureMeasuresOnlyFreshCountersAndStopsOnReset(t *testing.T) {
	now := time.Unix(100, 0)
	base := Traffic{Samples: 5, SentBytes: 100, ReceivedBytes: 200}
	var c FlowCapture
	c.Start(now, base, "iPad")
	c.Observe(now.Add(time.Second), base, "iPad", true)
	if c.Result.Status != "waiting" {
		t.Fatal("stale sample became baseline")
	}
	base.Samples++
	c.Observe(now.Add(2*time.Second), base, "iPad", true)
	next := base
	next.Samples++
	next.SentBytes += 30000000
	next.ReceivedBytes += 15000000
	c.Observe(now.Add(32*time.Second), next, "iPad", true)
	if c.Result.Status != "complete" || c.Result.TransmitMbps != 8 || c.Result.ReceiveMbps != 4 {
		t.Fatal(c.Result)
	}
	c.Start(now, next, "iPad")
	next.CounterResets++
	c.Observe(now.Add(time.Second), next, "iPad", true)
	if c.Result.Status != "failed" {
		t.Fatal("reset accepted")
	}
	c.Start(now, base, "Mac")
	c.Observe(now.Add(time.Second), base, "Mac", false)
	if c.Result.Status != "failed" {
		t.Fatal("disconnect accepted")
	}
}

func TestIdleTrafficIsNotReportedAsSuccessfulSpeedTest(t *testing.T) {
	now := time.Unix(100, 0)
	var c FlowCapture
	c.Start(now, Traffic{}, "Mac")
	c.Observe(now.Add(time.Second), Traffic{Samples: 1}, "Mac", true)
	c.Observe(now.Add(31*time.Second), Traffic{Samples: 2}, "Mac", true)
	if c.Result.Status != "idle" || c.Result.Seconds != 30 {
		t.Fatal(c.Result)
	}
}
func TestFlowCapturePreservesLowRateAndRejectsMissingSamples(t *testing.T) {
	now := time.Unix(100, 0)
	var c FlowCapture
	c.Start(now, Traffic{}, "Mac")
	c.Observe(now.Add(time.Second), Traffic{Samples: 1}, "Mac", true)
	c.Observe(now.Add(31*time.Second), Traffic{Samples: 2, SentBytes: 12000}, "Mac", true)
	if c.Result.Status != "complete" || c.Result.TransmitMbps != .0032 {
		t.Fatal(c.Result)
	}
	c.Start(now, Traffic{}, "Mac")
	c.Observe(now.Add(51*time.Second), Traffic{}, "Mac", true)
	if c.Result.Status != "failed" {
		t.Fatal("missing samples silently accepted")
	}
}
