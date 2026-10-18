package coreupdatenotice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func testBroker() *Broker {
	return &Broker{timeout: time.Second, visible: 5 * time.Millisecond, verify: func(Client) error { return nil }}
}

var goodClient = Client{PID: 20, Session: 1, Creation: 12345}

func waitNotice(t *testing.T, b *Broker, c Client) *Notice {
	t.Helper()
	limit := time.Now().Add(time.Second)
	for time.Now().Before(limit) {
		if n := b.Snapshot(c); n != nil {
			return n
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pending notice absent")
	return nil
}
func startNotice(b *Broker, ctx context.Context, phase string) <-chan error {
	done := make(chan error, 1)
	go func() { done <- b.Notify(ctx, "0.8.101", phase) }()
	return done
}
func TestNoticeDoesNotCompleteOnQueueOrDeliveryAndBindsExactClient(t *testing.T) {
	b := testBroker()
	done := startNotice(b, context.Background(), "received")
	n := waitNotice(t, b, goodClient)
	select {
	case <-done:
		t.Fatal("delivery manufactured renderer acknowledgement")
	default:
	}
	for _, c := range []Client{{PID: 21, Session: 1, Creation: 12345}, {PID: 20, Session: 2, Creation: 12345}, {PID: 20, Session: 1, Creation: 12346}, {PID: 20, Session: 1}, {PID: 20, Session: 0, Creation: 12345}} {
		if b.Snapshot(c) != nil || b.Reply(c, *n) == nil {
			t.Fatal("foreign PID/session/creation acknowledged")
		}
	}
	for _, change := range []Notice{{ID: strings.Repeat("a", 32), Version: n.Version, Phase: n.Phase}, {ID: n.ID, Version: "0.8.102", Phase: n.Phase}, {ID: n.ID, Version: n.Version, Phase: "installing"}} {
		if b.Reply(goodClient, change) == nil {
			t.Fatal("changed nonce/version/phase accepted")
		}
	}
	if e := b.Reply(goodClient, *n); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if b.Reply(goodClient, *n) == nil || b.Snapshot(goodClient) != nil {
		t.Fatal("stale receipt retained")
	}
}
func TestNoticeTimeoutCancelAndConcurrentPublicationFailClosed(t *testing.T) {
	b := testBroker()
	ctx, cancel := context.WithCancel(context.Background())
	done := startNotice(b, ctx, "received")
	n := waitNotice(t, b, goodClient)
	if b.Notify(context.Background(), "0.8.101", "received") == nil {
		t.Fatal("concurrent notice replaced owner")
	}
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if b.Reply(goodClient, *n) == nil {
		t.Fatal("cancelled notice acknowledged")
	}
	b = testBroker()
	b.timeout = 200 * time.Millisecond // well above the ~16ms Windows timer tick, so the notice is polled before it expires
	done = startNotice(b, context.Background(), "received")
	n = waitNotice(t, b, goodClient)
	if e := <-done; !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("missing renderer did not time out", e)
	}
	if b.Reply(goodClient, *n) == nil {
		t.Fatal("expired nonce accepted")
	}
}
func TestInstallingNoticeRetainsVisibleTimeAndCancellation(t *testing.T) {
	b := testBroker()
	b.visible = 30 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := startNotice(b, ctx, "installing")
	n := waitNotice(t, b, goodClient)
	if e := b.Reply(goodClient, *n); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
		t.Fatal("install started before visibility interval")
	case <-time.After(5 * time.Millisecond):
	}
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal("service cancellation discarded", e)
	}
	b = testBroker()
	done = startNotice(b, context.Background(), "installing")
	n = waitNotice(t, b, goodClient)
	started := time.Now()
	_ = b.Reply(goodClient, *n)
	if e := <-done; e != nil || time.Since(started) < b.visible {
		t.Fatal("visibility wait not preserved", e)
	}
}
func TestNoticeInputBoundsAndNoReplyWithoutDelivery(t *testing.T) {
	b := testBroker()
	for _, v := range []string{"", "1", "1.2.3.4", "1..3", "1.2.3/evil", strings.Repeat("1", 41)} {
		if b.Notify(context.Background(), v, "received") == nil {
			t.Fatal("invalid version", v)
		}
	}
	if b.Notify(nil, "0.8.101", "received") == nil || b.Notify(context.Background(), "0.8.101", "execute") == nil {
		t.Fatal("invalid context/phase")
	}
	done := startNotice(b, context.Background(), "received")
	n := waitNotice(t, b, goodClient)
	_ = b.Reply(goodClient, *n)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestNoticeRequiresRealClientStillAliveAfterRendererReply(t *testing.T) {
	b := testBroker()
	b.verify = func(Client) error { return errors.New("UI source or lifetime exited") }
	done := startNotice(b, context.Background(), "received")
	n := waitNotice(t, b, goodClient)
	_ = b.Reply(goodClient, *n)
	if <-done == nil {
		t.Fatal("renderer ack outlived client authority")
	}
	b = testBroker()
	calls := 0
	b.verify = func(Client) error {
		calls++
		if calls == 2 {
			return errors.New("UI exited during visibility")
		}
		return nil
	}
	done = startNotice(b, context.Background(), "installing")
	n = waitNotice(t, b, goodClient)
	_ = b.Reply(goodClient, *n)
	if <-done == nil {
		t.Fatal("installation continued after UI exit")
	}
}

func TestNoticeProceedsWhenNoUIClaimsIt(t *testing.T) {
	b := testBroker()
	b.claim = 20 * time.Millisecond
	if err := b.Notify(context.Background(), "0.8.128", "received"); err != nil {
		t.Fatalf("unclaimed notice must not block upgrade: %v", err)
	}
}
