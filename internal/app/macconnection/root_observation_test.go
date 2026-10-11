package macconnection

import (
	"errors"
	"sync"
	"testing"
)

func TestRootObservationInvalidationAndRetry(t *testing.T) {
	events := make(chan struct{}, 1)
	o := rootObservation{events: events}
	calls := 0
	value := "root-A"
	var err error
	query := func() (string, error) { calls++; return value, err }
	for i := 0; i < 100; i++ {
		if o.current(query, false) != "root-A" {
			t.Fatal("identity changed")
		}
	}
	if calls != 1 {
		t.Fatal("idle enumeration", calls)
	}
	value = "root-B"
	events <- struct{}{}
	if o.current(query, false) != "root-B" || calls != 2 {
		t.Fatal("swap missed")
	}
	err = errors.New("unreadable")
	events <- struct{}{}
	if o.current(query, false) != "" {
		t.Fatal("failure retained identity")
	}
	err = nil
	value = ""
	if o.current(query, false) != "" || calls != 4 {
		t.Fatal("unreadable not retried")
	}
	value = "root-C"
	events <- struct{}{}
	if o.current(query, false) != "root-C" {
		t.Fatal("reattach missed")
	}
	for i := 0; i < 10; i++ {
		o.current(query, true)
	}
	if calls != 15 {
		t.Fatal("baseline does not query", calls)
	}
}
func TestRootObservationEventDuringQueryIsNotLost(t *testing.T) {
	ch := make(chan struct{}, 1)
	o := rootObservation{events: ch}
	calls := 0
	query := func() (string, error) {
		calls++
		if calls == 1 {
			ch <- struct{}{}
		}
		return "root", nil
	}
	o.current(query, false)
	o.current(query, false)
	if calls != 2 {
		t.Fatal("racing event lost")
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); o.current(query, false) }()
	}
	wg.Wait()
	if calls != 2 {
		t.Fatal("concurrent cache not shared")
	}
}
func TestRootObservationRegistrationFallbackQueriesEveryCall(t *testing.T) {
	o := rootObservation{}
	calls := 0
	for i := 0; i < 10; i++ {
		o.current(func() (string, error) { calls++; return "root", nil }, false)
	}
	if calls != 10 {
		t.Fatal("registration failure cached", calls)
	}
}
