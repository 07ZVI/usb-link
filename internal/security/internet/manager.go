package internet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"suhang/usbnet/internal/transport/routing"
	"sync"
)

type Upstream struct {
	Index              uint32   `json:"index"`
	LUID               uint64   `json:"luid"`
	Name               string   `json:"name"`
	DNS                []string `json:"dns"`
	Excluded           []string `json:"excluded"`
	OriginalForwarding bool     `json:"original_forwarding"`
}
type Plan struct {
	CoreExecutable string   `json:"core_executable,omitempty"`
	DNSInterfaces  []string `json:"dns_interfaces,omitempty"`
	Epoch          string   `json:"epoch"`
	NAT            string   `json:"nat"`
	Root           string   `json:"root"`
	HostIndex      uint32   `json:"host_index"`
	HostLUID       uint64   `json:"host_luid"`
	Upstream       Upstream `json:"upstream"`
}
type Status struct {
	State     string              `json:"state"`
	Problem   string              `json:"problem,omitempty"`
	Plan      *Plan               `json:"plan,omitempty"`
	Upstreams []Upstream          `json:"upstreams"`
	Client    routing.Observation `json:"client"`
}
type Backend interface {
	Preflight(context.Context, uint32) (Upstream, error)
	Journal(Plan) error
	Create(context.Context, Plan) error
	Open(context.Context, Plan) (func() error, error)
	Close(context.Context, Plan) error
	Clear(Plan) error
	Healthy(context.Context, Plan) bool
}
type Manager struct {
	mu        sync.Mutex
	backend   Backend
	state     Status
	stop      func() error
	Authorize func() (string, uint32, uint64, bool)
}

func New(b Backend, authorize func() (string, uint32, uint64, bool)) *Manager {
	return &Manager{backend: b, Authorize: authorize, state: Status{State: "off", Upstreams: []Upstream{}}}
}
func (m *Manager) Snapshot() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state
	if s.Plan != nil {
		p := *s.Plan
		s.Plan = &p
	}
	return s
}
func (m *Manager) Enable(ctx context.Context, index uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Plan != nil {
		return errors.New("INTERNET_ALREADY_ACTIVE_OR_RECOVERY_REQUIRED")
	}
	root, host, luid, ok := m.Authorize()
	if !ok || root == "" || host == 0 || luid == 0 {
		return errors.New("INTERNET_MAC_AUTHORIZATION_REQUIRED")
	}
	up, e := m.backend.Preflight(ctx, index)
	if e != nil {
		m.state = Status{State: "unavailable", Problem: e.Error()}
		return e
	}
	if up.Index == host || up.LUID == luid {
		return errors.New("INTERNET_USB_UPSTREAM_REJECTED")
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	epoch := hex.EncodeToString(nonce[:])
	p := Plan{Epoch: epoch, NAT: "USBLink-" + epoch, Root: root, HostIndex: host, HostLUID: luid, Upstream: up}
	m.state = Status{State: "preparing", Plan: &p}
	if e = m.backend.Journal(p); e != nil {
		m.state = Status{State: "failed", Problem: e.Error()}
		return e
	}
	if e = m.backend.Create(ctx, p); e == nil {
		m.stop, e = m.backend.Open(ctx, p)
	}
	if e != nil {
		original := e
		if cleanup := m.disableLocked(context.Background()); cleanup != nil {
			m.state.Problem = original.Error() + "; " + cleanup.Error()
		}
		return original
	}
	r, i, l, valid := m.Authorize()
	if !valid || r != root || i != host || l != luid {
		_ = m.disableLocked(context.Background())
		return errors.New("INTERNET_DEVICE_CHANGED")
	}
	m.state.State = "waiting_client"
	return nil
}
func (m *Manager) Disable(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disableLocked(ctx)
}
func (m *Manager) disableLocked(ctx context.Context) error {
	if m.state.Plan == nil {
		m.state = Status{State: "off"}
		return nil
	}
	p := *m.state.Plan
	m.state.State = "stopping"
	if m.stop != nil {
		if e := m.stop(); e != nil {
			m.state.State = "recovery_required"
			m.state.Problem = e.Error()
			return e
		}
		m.stop = nil
	}
	if e := m.backend.Close(ctx, p); e != nil {
		m.state.State = "recovery_required"
		m.state.Problem = e.Error()
		return e
	}
	if e := m.backend.Clear(p); e != nil {
		m.state.State = "recovery_required"
		m.state.Problem = e.Error()
		return e
	}
	m.state = Status{State: "off"}
	return nil
}
func (m *Manager) Observe(ctx context.Context, o routing.Observation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Plan == nil {
		return
	}
	if m.state.State != "ready" && m.state.State != "waiting_client" {
		return
	}
	p := *m.state.Plan
	r, i, l, valid := m.Authorize()
	if !valid || r != p.Root || i != p.HostIndex || l != p.HostLUID || !m.backend.Healthy(ctx, p) {
		_ = m.disableLocked(context.Background())
		return
	}
	if o.Epoch == p.Epoch {
		m.state.Client = o
		if o.DHCPACK && o.Outbound && o.Inbound {
			m.state.State = "ready"
		}
	}
}
