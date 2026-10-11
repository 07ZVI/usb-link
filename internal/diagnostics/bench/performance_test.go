package bench

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestProfileBufferBounds(t *testing.T) {
	b := &boundedProfile{limit: 3}
	if n, e := b.Write([]byte("ab")); n != 2 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := b.Write([]byte("cd")); n != 1 || e == nil {
		t.Fatal(n, e)
	}
	p, e := b.result()
	if string(p) != "abc" || e == nil {
		t.Fatal(string(p), e)
	}
	if n, e := b.Write([]byte("x")); n != 0 || e == nil {
		t.Fatal(n, e)
	}
}
func TestPerformanceRejectsUnboundedRequests(t *testing.T) {
	nonce := "0123456789abcdef0123456789abcdef"
	for _, f := range [][]string{{PerfProtocol, "CPU", "31", nonce}, {PerfProtocol, "TRACE", "6", nonce}, {PerfProtocol, "HEAP", "1", nonce}, {PerfProtocol, "EXEC", "0", nonce}, {PerfProtocol, "GC800", "0", "bad"}, {PerfProtocol, "CPU", "1", nonce, "extra"}} {
		var b bytes.Buffer
		if e := handlePerformance(context.Background(), &b, f); e == nil {
			t.Fatal(f)
		}
		if b.Len() != 0 {
			t.Fatal("responded to invalid request")
		}
	}
}
func TestPerformanceCaptureBusy(t *testing.T) {
	captureMu.Lock()
	defer captureMu.Unlock()
	var b bytes.Buffer
	if e := handlePerformance(context.Background(), &b, []string{PerfProtocol, "CPU", "1", "0123456789abcdef0123456789abcdef"}); e == nil {
		t.Fatal("accepted simultaneous capture")
	}
}
func TestPerformanceCancelledBeforeResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var b bytes.Buffer
	e := handlePerformance(ctx, &b, []string{PerfProtocol, "HEAP", "0", "0123456789abcdef0123456789abcdef"})
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = io.Copy(io.Discard, &b); e != nil {
		t.Fatal(e)
	}
}

func TestWinUSBComparisonPreservesBuffersAndRestoresDefault(t *testing.T) {
	defer RestoreGC()
	for _, kind := range []string{"USBORIGINAL", "USBCACHED", "USBORIGINAL", "DEFAULT"} {
		if e := ValidatePerformance(kind, 0, "0123456789abcdef0123456789abcdef"); e != nil {
			t.Fatal(e)
		}
		setGC(kind)
		if !ReuseBuffers() || CachedWinUSB() != (kind != "USBORIGINAL") {
			t.Fatal("comparison changed unrelated buffers or native call mode", kind)
		}
		_, percent, limit := GCSettings()
		if percent != gcBasePercent || limit != gcBaseLimit {
			t.Fatal("comparison changed GC", kind)
		}
	}
	setGC("USBORIGINAL")
	RestoreGC()
	if !CachedWinUSB() || !ReuseBuffers() {
		t.Fatal("default restoration failed")
	}
}
