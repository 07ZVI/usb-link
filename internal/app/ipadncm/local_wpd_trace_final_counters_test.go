//go:build usblink_local_remote

package ipadncm

import "testing"

type wpdFinalCounterBackend struct {
	wpdFake
	value localWPDTraceSample
}

func (b *wpdFinalCounterBackend) sample() (localWPDTraceSample, error) { return b.value, nil }
func (b *wpdFinalCounterBackend) cachedSample() localWPDTraceSample    { return b.value }
func (b *wpdFinalCounterBackend) stop() error {
	b.stops.Add(1)
	b.value.Events = 9
	return b.stopErr
}

func TestLocalWPDTraceStopPublishesFinalCachedCounters(t *testing.T) {
	for _, failed := range []bool{false, true} {
		b := &wpdFinalCounterBackend{value: localWPDTraceSample{Events: 3}}
		c := newLocalWPDTraceController()
		armWPD(c, &b.wpdFake)
		c.backend = b
		c.step()
		if failed {
			b.stopErr = wpdTraceError("WPD_TRACE_STOP_FAILED", 5)
		}
		c.masterChanged(false)
		c.step()
		s := c.snapshot()
		if s.Events != 9 || s.Effective || failed && s.Phase != "recovery_pending" || !failed && s.Phase != "off" {
			t.Fatal("stop lost drained consumer counters", failed, s)
		}
	}
}
