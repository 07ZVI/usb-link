package appfirewall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

type Storage interface {
	Load() (Store, error)
	Save(Store) error
}
type Executor interface {
	Inspect(context.Context, string) (Identity, error)
	Apply(context.Context, Change) error
}
type Auditor interface {
	Audit(context.Context, []Rule) ([]Rule, error)
}
type Manager struct {
	mu       sync.Mutex
	disk     Storage
	executor Executor
	state    Store
	problem  string
}

func New(ctx context.Context, disk Storage, executor Executor) (*Manager, error) {
	if disk == nil || executor == nil {
		return nil, fmt.Errorf("FIREWALL_EXECUTOR_UNAVAILABLE")
	}
	s, err := disk.Load()
	if err != nil {
		return nil, err
	}
	if !s.Valid() {
		return nil, fmt.Errorf("FIREWALL_STORE_INVALID")
	}
	m := &Manager{disk: disk, executor: executor, state: s}
	if s.Pending != nil {
		if err = m.commit(ctx, *s.Pending); err != nil {
			m.problem = err.Error()
		}
	}
	return m, nil
}

func (m *Manager) Snapshot() ([]Rule, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]Rule{}, m.state.Rules...)
	if c := m.state.Pending; c != nil {
		pending := c.Rule
		pending.State = "pending"
		pending.Error = m.problem
		found := false
		for i, r := range out {
			if r.ID == pending.ID {
				out[i] = pending
				found = true
				break
			}
		}
		if !found {
			out = append(out, pending)
		}
	}
	return out, m.problem
}

func (m *Manager) Audit(ctx context.Context) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if err != nil {
			for i := range m.state.Rules {
				m.state.Rules[i].State = "error"
				m.state.Rules[i].Error = "FIREWALL_READBACK_UNAVAILABLE"
			}
		}
	}()
	a, ok := m.executor.(Auditor)
	if !ok {
		return fmt.Errorf("FIREWALL_AUDIT_UNAVAILABLE")
	}
	rules, err := a.Audit(ctx, append([]Rule{}, m.state.Rules...))
	if err != nil {
		for i := range m.state.Rules {
			m.state.Rules[i].State = "error"
			m.state.Rules[i].Error = "FIREWALL_READBACK_UNAVAILABLE"
		}
		return err
	}
	if len(rules) != len(m.state.Rules) {
		return fmt.Errorf("FIREWALL_AUDIT_INVALID")
	}
	for i, r := range rules {
		intent := r
		intent.State = m.state.Rules[i].State
		intent.Error = m.state.Rules[i].Error
		if intent != m.state.Rules[i] || !r.Valid() || (r.State != "applied" && r.State != "error") {
			return fmt.Errorf("FIREWALL_AUDIT_INVALID")
		}
	}
	m.state.Rules = rules
	return nil
}

// Mutations are durable before OS calls. Failure retains a pending receipt and
// rejects new writes until that exact change is recovered. Existing OS rules
// owned by other applications are never imported, replaced or broadly removed.
func (m *Manager) commit(ctx context.Context, c Change) error {
	if err := m.executor.Apply(ctx, c); err != nil {
		m.problem = err.Error()
		return err
	}
	next := m.state
	next.Rules = append([]Rule{}, m.state.Rules...)
	next.Pending = nil
	idx := -1
	for i, r := range next.Rules {
		if r.ID == c.Rule.ID {
			idx = i
			break
		}
	}
	if c.Operation == "delete" {
		if idx >= 0 {
			next.Rules = append(next.Rules[:idx], next.Rules[idx+1:]...)
		}
	} else {
		c.Rule.State = "applied"
		c.Rule.Error = ""
		if idx >= 0 {
			next.Rules[idx] = c.Rule
		} else {
			next.Rules = append(next.Rules, c.Rule)
		}
	}
	if err := m.disk.Save(next); err != nil {
		m.problem = "FIREWALL_RESULT_NOT_SAVED"
		return err
	}
	m.state = next
	m.problem = ""
	return nil
}

func (m *Manager) recover(ctx context.Context) error {
	if m.state.Pending != nil {
		return m.commit(ctx, *m.state.Pending)
	}
	return nil
}

func (m *Manager) change(ctx context.Context, c Change) error {
	next := m.state
	next.Pending = &c
	if err := m.disk.Save(next); err != nil {
		return err
	}
	m.state = next
	return m.commit(ctx, c)
}

func (m *Manager) Upsert(ctx context.Context, r Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.recover(ctx); err != nil {
		return err
	}
	if len(m.state.Rules) >= 256 && r.ID == "" {
		return fmt.Errorf("FIREWALL_RULE_LIMIT")
	}
	if r.ID != "" {
		if err := ValidateID(r.ID); err != nil {
			return err
		}
		found := false
		for _, old := range m.state.Rules {
			if old.ID == r.ID {
				found = true
				r.Application = old.Application
				break
			}
		}
		if !found {
			return fmt.Errorf("FIREWALL_RULE_NOT_FOUND")
		}
	}
	id, err := m.executor.Inspect(ctx, r.Application.Path)
	if err != nil {
		return err
	}
	if r.ID != "" && id.SHA256 != r.Application.SHA256 {
		return fmt.Errorf("FIREWALL_APPLICATION_CHANGED_REMOVE_AND_REVIEW")
	}
	r.Application = id
	r.State = "pending"
	r.Error = ""
	if r.ID == "" {
		var b [16]byte
		if _, err = rand.Read(b[:]); err != nil {
			return err
		}
		r.ID = hex.EncodeToString(b[:])
	}
	if !r.Valid() {
		return fmt.Errorf("FIREWALL_RULE_INVALID")
	}
	return m.change(ctx, Change{Operation: "upsert", Rule: r})
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ValidateID(id); err != nil {
		return err
	}
	if err := m.recover(ctx); err != nil {
		return err
	}
	for _, r := range m.state.Rules {
		if r.ID == id {
			return m.change(ctx, Change{Operation: "delete", Rule: r})
		}
	}
	return fmt.Errorf("FIREWALL_RULE_NOT_FOUND")
}

func (m *Manager) RemoveAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.discardPending(ctx); err != nil {
		return err
	}
	for len(m.state.Rules) > 0 {
		if err := m.change(ctx, Change{Operation: "delete", Rule: m.state.Rules[0]}); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) discardPending(ctx context.Context) error {
	c := m.state.Pending
	if c == nil {
		return nil
	}
	if err := m.executor.Apply(ctx, Change{Operation: "delete", Rule: c.Rule}); err != nil {
		return err
	}
	next := m.state
	next.Pending = nil
	next.Rules = append([]Rule{}, m.state.Rules...)
	for i, r := range next.Rules {
		if r.ID == c.Rule.ID {
			next.Rules = append(next.Rules[:i], next.Rules[i+1:]...)
			break
		}
	}
	if err := m.disk.Save(next); err != nil {
		return err
	}
	m.state = next
	m.problem = ""
	return nil
}
func (m *Manager) DiscardPending(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.discardPending(ctx)
}
