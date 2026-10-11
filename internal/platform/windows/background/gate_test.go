package background

import "testing"

func TestConsentDoesNotSurviveDisconnectOrDeviceChange(t *testing.T) {
	g := Gate{}
	if g.CanAsk() || g.Decide("", true) {
		t.Fatal("no device must not connect")
	}
	g.Observe("A")
	if !g.CanAsk() || !g.Decide("A", true) || g.CanAsk() {
		t.Fatal("one approval per attachment")
	}
	g.Observe("")
	g.Observe("A")
	if !g.CanAsk() {
		t.Fatal("replug must ask again")
	}
	g.Observe("B")
	if g.Decide("A", true) || !g.CanAsk() {
		t.Fatal("stale approval must not authorize another device")
	}
}
func TestDeclineTimeoutAndRetry(t *testing.T) {
	g := Gate{}
	g.Observe("A")
	if g.Decide("A", false) || g.CanAsk() {
		t.Fatal("decline must remain disconnected")
	}
	g.Observe("A")
	if g.CanAsk() {
		t.Fatal("same attachment must not spam prompts")
	}
	g.Retry()
	if !g.CanAsk() || !g.Decide("A", true) {
		t.Fatal("explicit retry still requires new consent")
	}
}
