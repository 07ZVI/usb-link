package ipadncm

import (
	"context"
	"testing"
	"time"
)

func TestRemoveTraysWaitsForAcknowledgement(t *testing.T) {
	acks := []*trayRemovalAck{newTrayRemovalAck(), newTrayRemovalAck()}
	posted := 0
	ok := removeTraysAndWait(acks, func(i int) { posted++; go acks[i].release() }, time.Second)
	if !ok || posted != 2 {
		t.Fatalf("ok=%v posted=%d", ok, posted)
	}
}

func TestRemoveTraysTimesOutWhenWindowThreadIsStuck(t *testing.T) {
	acks := []*trayRemovalAck{newTrayRemovalAck()}
	start := time.Now()
	if removeTraysAndWait(acks, func(int) {}, 50*time.Millisecond) {
		t.Fatal("must report failure")
	}
	if time.Since(start) > time.Second {
		t.Fatal("wait not bounded")
	}
}

func TestTrayRemovedBeforeTermination(t *testing.T) {
	var order []string
	terminateAfterTrayRemoval(func() bool { order = append(order, "remove"); return true }, func() { order = append(order, "terminate") })
	if len(order) != 2 || order[0] != "remove" {
		t.Fatalf("order=%v", order)
	}
}

func TestTrayRemovalRequestedOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	requested := make(chan struct{})
	removeTrayOnCancel(ctx, func() { close(requested) })
	select {
	case <-requested:
		t.Fatal("requested before cancel")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-requested:
	case <-time.After(time.Second):
		t.Fatal("not requested after cancel")
	}
}
