package internet

import (
	"context"
	"errors"
	"suhang/usbnet/internal/transport/routing"
	"testing"
)

type fakeBackend struct {
	calls   []string
	fail    string
	healthy bool
	epoch   string
}

func (b *fakeBackend) step(s string) error {
	b.calls = append(b.calls, s)
	if b.fail == s {
		return errors.New(s)
	}
	return nil
}
func (b *fakeBackend) Preflight(context.Context, uint32) (Upstream, error) {
	return Upstream{Index: 2, LUID: 20}, b.step("preflight")
}
func (b *fakeBackend) Journal(p Plan) error               { b.epoch = p.Epoch; return b.step("journal") }
func (b *fakeBackend) Create(context.Context, Plan) error { return b.step("create") }
func (b *fakeBackend) Open(context.Context, Plan) (func() error, error) {
	e := b.step("open")
	return func() error { return b.step("block") }, e
}
func (b *fakeBackend) Close(context.Context, Plan) error  { return b.step("close") }
func (b *fakeBackend) Clear(Plan) error                   { return b.step("clear") }
func (b *fakeBackend) Healthy(context.Context, Plan) bool { return b.healthy }
func TestManualGrantDHCPReadbackAndImmediateRevocation(t *testing.T) {
	b := &fakeBackend{healthy: true}
	authorized := true
	m := New(b, func() (string, uint32, uint64, bool) { return "mac", 1, 10, authorized })
	ctx := context.Background()
	if m.Snapshot().State != "off" {
		t.Fatal("default on")
	}
	if e := m.Enable(ctx, 0); e != nil {
		t.Fatal(e)
	}
	m.Observe(ctx, routing.Observation{Epoch: b.epoch, Outbound: true, Inbound: true})
	if m.Snapshot().State != "waiting_client" {
		t.Fatal("DHCP unproven")
	}
	m.Observe(ctx, routing.Observation{Epoch: b.epoch, DHCPACK: true, Outbound: true, Inbound: true})
	if m.Snapshot().State != "ready" {
		t.Fatal("readback not accepted")
	}
	authorized = false
	m.Observe(ctx, routing.Observation{})
	if m.Snapshot().State != "off" {
		t.Fatal("revocation ignored")
	}
	n := len(b.calls)
	if b.calls[n-3] != "block" || b.calls[n-2] != "close" || b.calls[n-1] != "clear" {
		t.Fatal(b.calls)
	}
}
func TestFailureCleanupRetainsRecoveryAndSupportsRetry(t *testing.T) {
	b := &fakeBackend{healthy: true, fail: "open"}
	m := New(b, func() (string, uint32, uint64, bool) { return "mac", 1, 10, true })
	if m.Enable(context.Background(), 0) == nil || m.Snapshot().State != "off" {
		t.Fatal(m.Snapshot())
	}
	b.fail = ""
	if e := m.Enable(context.Background(), 0); e != nil {
		t.Fatal(e)
	}
	b.fail = "close"
	if m.Disable(context.Background()) == nil || m.Snapshot().Plan == nil || m.Snapshot().State != "recovery_required" {
		t.Fatal("journal lost")
	}
	b.fail = ""
	if e := m.Disable(context.Background()); e != nil || m.Snapshot().State != "off" {
		t.Fatal(e)
	}
}
func TestNoDeviceNeverMutatesSystem(t *testing.T) {
	b := &fakeBackend{}
	m := New(b, func() (string, uint32, uint64, bool) { return "", 0, 0, false })
	if m.Enable(context.Background(), 0) == nil || len(b.calls) != 0 {
		t.Fatal("unauthorized mutation")
	}
}
func TestRecoveryCannotBeReenabledByOldObservation(t *testing.T) {
	b := &fakeBackend{healthy: true}
	m := New(b, func() (string, uint32, uint64, bool) { return "mac", 1, 10, true })
	ctx := context.Background()
	if e := m.Enable(ctx, 0); e != nil {
		t.Fatal(e)
	}
	b.fail = "close"
	_ = m.Disable(ctx)
	m.Observe(ctx, routing.Observation{Epoch: b.epoch, DHCPACK: true, Outbound: true, Inbound: true})
	if m.Snapshot().State != "recovery_required" {
		t.Fatal("old observation reopened failed cleanup")
	}
}
