package bench

import (
	"testing"
	"time"
)

func TestEventWaitExperimentReturnsToProductionPolling(t *testing.T) {
	SetEventWaitExperiment(0)
	t.Cleanup(func() { SetEventWaitExperiment(0) })
	if EventWaits() {
		t.Fatal("production default must retain polling")
	}
	setEventWaitDuration(20 * time.Millisecond)
	if !EventWaits() {
		t.Fatal("bounded event experiment not enabled")
	}
	deadline := time.Now().Add(time.Second)
	for EventWaits() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if EventWaits() {
		t.Fatal("experiment did not expire to production polling")
	}
	setEventWaitDuration(10 * time.Millisecond)
	setEventWaitDuration(100 * time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	if !EventWaits() {
		t.Fatal("old expiry stopped newer experiment")
	}
	SetEventWaitExperiment(0)
	if EventWaits() {
		t.Fatal("explicit restore failed")
	}
	for _, item := range []struct {
		kind    string
		seconds int
	}{{"WAITDEFAULT", 0}, {"WAITBASELINE", 120}, {"WAITEVENTS", 120}, {"WAITEVENTSLONG", 900}, {"WAITEVENTSHOUR", 3900}, {"FREEMEMORY", 0}} {
		if err := ValidatePerformance(item.kind, item.seconds, "0123456789abcdef0123456789abcdef"); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		kind    string
		seconds int
	}{{"WAITDEFAULT", 120}, {"WAITEVENTS", 0}, {"WAITEVENTS", 121}, {"WAITBASELINE", 0}, {"WAITEVENTSLONG", 899}, {"WAITEVENTSLONG", 901}, {"WAITEVENTSHOUR", 3899}, {"WAITEVENTSHOUR", 3901}, {"FREEMEMORY", 1}} {
		if ValidatePerformance(item.kind, item.seconds, "0123456789abcdef0123456789abcdef") == nil {
			t.Fatal("unbounded or invalid command accepted", item)
		}
	}
}

// A mode change after the caller reset its native notification must remain
// visible even if the native wait has not started yet. Both workers need their
// own notification; one cannot consume the other's transition.
func TestModeTransitionCannotOvertakeResetAndRead(t *testing.T) {
	SetEventWaitExperiment(0)
	defer SetEventWaitExperiment(0)
	notifications := []chan struct{}{make(chan struct{}, 1), make(chan struct{}, 1)}
	stops := []func(){}
	for _, ch := range notifications {
		stops = append(stops, ObserveEventWaitMode(func() {
			select {
			case ch <- struct{}{}:
			default:
			}
		}))
	}
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()
	resetEntered, releaseReset := make(chan struct{}), make(chan struct{})
	readDone := make(chan bool, 1)
	go func() { readDone <- ReadEventWaitMode(func() { close(resetEntered); <-releaseReset }) }()
	<-resetEntered
	changed := make(chan struct{})
	go func() { SetEventWaitExperiment(120); close(changed) }()
	close(releaseReset)
	if <-readDone {
		t.Fatal("transition overtook locked reset/read")
	}
	<-changed
	for _, ch := range notifications {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("worker missed transition")
		}
	}
	SetEventWaitExperiment(0)
	for _, ch := range notifications {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("worker missed explicit restore")
		}
	}
}

func TestLeaseExpiryNotifiesBlockedWorkersAndUnsubscribeJoins(t *testing.T) {
	SetEventWaitExperiment(0)
	defer SetEventWaitExperiment(0)
	wakes := make(chan struct{}, 4)
	unsubscribe := ObserveEventWaitMode(func() { wakes <- struct{}{} })
	setEventWaitDuration(20 * time.Millisecond)
	<-wakes
	select {
	case <-wakes:
	case <-time.After(time.Second):
		t.Fatal("expiry only changed bool without waking native wait")
	}
	if EventWaits() {
		t.Fatal("expiry did not restore default")
	}
	unsubscribe()
	SetEventWaitExperiment(120)
	select {
	case <-wakes:
		t.Fatal("callback after native event owner unsubscribed")
	default:
	}
}
