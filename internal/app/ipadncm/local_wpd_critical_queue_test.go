//go:build usblink_local_remote

package ipadncm

import (
	"sync"
	"testing"
)

func validWPDCriticalCapture() wpdCriticalCapture {
	return wpdCriticalCapture{providerMatched: true, id: 2000, headerSize: 80, dataLength: 2, dataPointer: true}
}
func TestWPDCriticalAdmissionRejectsBeforeCopy(t *testing.T) {
	tests := []struct {
		name   string
		change func(*wpdCriticalCapture)
		reason string
	}{
		{"provider", func(c *wpdCriticalCapture) { c.providerMatched = false }, "provider_unproven"},
		{"id", func(c *wpdCriticalCapture) { c.id = 2004 }, "event_not_selected"},
		{"version", func(c *wpdCriticalCapture) { c.version = 1 }, "version_not_selected"},
		{"header", func(c *wpdCriticalCapture) { c.headerSize = 79 }, "header_size_invalid"},
		{"extended_count", func(c *wpdCriticalCapture) { c.extendedCount = 1 }, "extended_data_unsupported"},
		{"extended_pointer", func(c *wpdCriticalCapture) { c.extendedPointer = true }, "extended_data_unsupported"},
		{"extended_flag", func(c *wpdCriticalCapture) { c.flags = 1 }, "extended_data_unsupported"},
		{"zero", func(c *wpdCriticalCapture) { c.dataLength = 0 }, "payload_size_invalid"},
		{"oversize", func(c *wpdCriticalCapture) { c.dataLength = 4097 }, "payload_size_invalid"},
		{"null", func(c *wpdCriticalCapture) { c.dataPointer = false }, "payload_size_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := newWPDCriticalQueue()
			c := validWPDCriticalCapture()
			tt.change(&c)
			got := q.enqueue(c, func(*wpdCriticalItem) { t.Fatal("copied rejected native memory") })
			if got != tt.reason {
				t.Fatal(got)
			}
			s := q.snapshot()
			if s.Seen != 1 || s.Rejected != 1 || s.Enqueued != 0 {
				t.Fatal(s)
			}
			if (s.RejectedExtended == 1) != (tt.reason == "extended_data_unsupported") || (s.RejectedLength == 1) != (tt.reason == "payload_size_invalid") {
				t.Fatal(s)
			}
		})
	}
	c := validWPDCriticalCapture()
	c.summary = true
	c.id = 2004
	c.version = 255
	c.providerMatched = false
	c.dataLength = 0
	c.dataPointer = false
	if c.rejection() != "" {
		t.Fatal("summary must preserve metadata-only event admission")
	}
}
func TestWPDCriticalIndependentCapacityCopyAndDrain(t *testing.T) {
	q, summary := newWPDCriticalQueue(), newWPDCriticalQueue()
	c := validWPDCriticalCapture()
	for i := 0; i < 128; i++ {
		if got := q.enqueue(c, func(v *wpdCriticalItem) {
			v.payload[0] = byte(i)
			v.header[0] = 80
			v.ms = int64(100 + i)
			v.attempt = 7
		}); got != "" {
			t.Fatal(got)
		}
	}
	if q.enqueue(c, func(*wpdCriticalItem) { t.Fatal("overflow copy") }) != "queue_full" {
		t.Fatal("missing overflow")
	}
	if summary.enqueue(c, func(*wpdCriticalItem) {}) != "" {
		t.Fatal("critical exhausted summary")
	}
	q.close()
	if q.enqueue(c, func(*wpdCriticalItem) { t.Fatal("closed copy") }) != "consumer_closed" {
		t.Fatal("accepted after close")
	}
	for i := 0; i < 128; i++ {
		v, ok, closed := q.pop()
		if !ok || closed || v.payload[0] != byte(i) || v.ms != int64(100+i) || v.attempt != 7 {
			t.Fatal(i, v.ms, ok, closed)
		}
		if q.items[i] != (wpdCriticalItem{}) {
			t.Fatal("private slot not cleared")
		}
		v.payload[0] = 255
		q.complete(i%2 == 0, i%3 == 0, i%2 == 0)
	}
	_, ok, closed := q.pop()
	s := q.snapshot()
	if ok || !closed || s.Pending != 0 || s.InFlight != 0 || s.Seen != 130 || s.Enqueued != 128 || s.Overflow != 1 || s.Rejected != 1 || s.Decoded != 64 || s.Failed != 64 || s.ArchiveEnqueued != 64 || s.ArchiveNotQueued != 64 || s.HighWater != 128 || !s.Closed {
		t.Fatal(s, ok, closed)
	}
	copied := s
	copied.Seen = 0
	if q.snapshot().Seen != 130 {
		t.Fatal("snapshot alias")
	}
}
func TestWPDCriticalConcurrentCloseAndAccounting(t *testing.T) {
	q := newWPDCriticalQueue()
	c := validWPDCriticalCapture()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, ok, closed := q.pop()
			if !ok {
				if closed {
					return
				}
				<-q.wake
				continue
			}
			q.complete(true, false, true)
		}
	}()
	var wg sync.WaitGroup
	for p := 0; p < 4; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				q.enqueue(c, func(v *wpdCriticalItem) { v.payload[0] = 42 })
				_ = q.snapshot()
			}
		}()
	}
	wg.Wait()
	q.close()
	<-done
	s := q.snapshot()
	if s.Seen != 2000 || s.Seen != s.Enqueued+s.Rejected+s.Overflow || s.Decoded != s.Enqueued || s.ArchiveEnqueued != s.Enqueued || s.Pending != 0 || s.InFlight != 0 {
		t.Fatal(s)
	}
	for _, slot := range q.items {
		if slot != (wpdCriticalItem{}) {
			t.Fatal("private bytes retained after drain")
		}
	}
}

func TestWPDEventRecordSizeIsNotHeaderAllocationSize(t *testing.T) {
	for _, summary := range []bool{false, true} {
		for _, size := range []uint16{80, 82, 112, 512, 65535} {
			c := validWPDCriticalCapture()
			c.summary = summary
			c.headerSize = size
			c.flags = 576
			q := newWPDCriticalQueue()
			if got := q.enqueue(c, func(v *wpdCriticalItem) { v.payload[0] = 2; v.payload[1] = 16 }); got != "" {
				t.Fatal("valid declared record size rejected", summary, size, got)
			}
			v, ok, _ := q.pop()
			if !ok || len(v.header) != 80 || len(v.payload) != 4096 || v.length != 2 {
				t.Fatal("declared size changed private copy bounds")
			}
			q.complete(false, false, false)
		}
		for _, size := range []uint16{0, 1, 79} {
			c := validWPDCriticalCapture()
			c.summary = summary
			c.headerSize = size
			if newWPDCriticalQueue().enqueue(c, func(*wpdCriticalItem) { t.Fatal("undersized record copied") }) != "header_size_invalid" {
				t.Fatal(summary, size)
			}
		}
	}
	// A large declared record does not bypass the independent payload/extended gates.
	c := validWPDCriticalCapture()
	c.headerSize = 65535
	c.dataLength = 4097
	if c.rejection() != "payload_size_invalid" {
		t.Fatal(c.rejection())
	}
	c.dataLength = 2
	c.extendedCount = 1
	if c.rejection() != "extended_data_unsupported" {
		t.Fatal(c.rejection())
	}
}
