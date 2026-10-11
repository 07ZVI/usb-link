//go:build windows && amd64

package usbgateway

import (
	"fmt"
	"golang.org/x/sys/windows"
	"sync"
	"time"
)

// TemporaryDiagnosticICMP journals unique keys before adding a bounded lease.
// Recovery removes only verified owned objects after an interrupted process.
func (m *Manager) TemporaryDiagnosticICMP(seconds int) (func() error, error) {
	if seconds < 1 || seconds > 120 {
		return nil, fmt.Errorf("GATEWAY_DIAGNOSTIC_DURATION_INVALID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	type group struct {
		sub   windows.GUID
		keys  []windows.GUID
		specs []Specification
	}
	groups := []group{}
	for luid, a := range m.links {
		if a.peer != "10.6.9.2" && luid != sharedHostLUID.Load() {
			continue
		}
		specs, e := DiagnosticICMPPolicy(luid)
		if e != nil {
			return nil, e
		}
		if len(a.keys)+len(specs) > 2048 {
			return nil, fmt.Errorf("GATEWAY_DIAGNOSTIC_JOURNAL_LIMIT")
		}
		g := group{sub: a.sub, specs: specs}
		for range specs {
			key, e := randomGUID()
			if e != nil {
				return nil, e
			}
			g.keys = append(g.keys, key)
		}
		groups = append(groups, g)
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("GATEWAY_MAC_INTERFACE_UNAVAILABLE")
	}
	for _, g := range groups {
		for _, a := range m.links {
			if a.sub == g.sub {
				a.keys = append(a.keys, g.keys...)
			}
		}
		for j := range m.conf.Journals {
			if m.conf.Journals[j].Sublayer == g.sub.String() {
				for _, key := range g.keys {
					m.conf.Journals[j].Keys = append(m.conf.Journals[j].Keys, key.String())
				}
			}
		}
	}
	if e := m.save(); e != nil {
		return nil, e
	}
	remove := func() error {
		return transaction(m.engine, func() error {
			for _, g := range groups {
				for _, key := range g.keys {
					if e := removeFilter(m.engine, key, g.sub); e != nil {
						return e
					}
				}
			}
			return nil
		})
	}
	e := transaction(m.engine, func() error {
		for _, g := range groups {
			for i, key := range g.keys {
				if _, e := addFilter(m.engine, key, g.sub, g.specs[i]); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	for _, g := range groups {
		for i, key := range g.keys {
			if e = verifyFilter(m.engine, key, g.sub, g.specs[i]); e != nil {
				if re := remove(); re != nil {
					return nil, fmt.Errorf("%w; diagnostic rollback: %v", e, re)
				}
				return nil, e
			}
		}
	}
	var once sync.Once
	var result error
	var timer *time.Timer
	cleanup := func() error {
		once.Do(func() {
			m.mu.Lock()
			if timer != nil {
				timer.Stop()
			}
			defer m.mu.Unlock()
			result = remove()
			if result != nil {
				m.problem = result.Error()
			}
		})
		return result
	}
	// Timer starts while the manager lock is held, so it cannot race publication.
	timer = time.AfterFunc(time.Duration(seconds)*time.Second, func() { cleanup() })
	return cleanup, nil
}
