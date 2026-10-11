//go:build windows && amd64

package usbgateway

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"sync"
)

// Add restrictions after the admitted iPad link exists and before its network
// services begin. A separate owned sublayer lets removal leave the Mac's
// existing shared-host permits and live attachment untouched.
func (m *Manager) RestrictIPadNetworkOnly(luid uint64) (func() error, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.links[luid]
	if a == nil || a.peer != "10.6.9.3" || luid == sharedHostLUID.Load() {
		return nil, fmt.Errorf("network-only admitted iPad interface required")
	}
	apps := []string{}
	for _, g := range effectiveGrants(m.conf.Grants, m.session) {
		if g.Decision == "allow" && appleSyncApplication(g.Path) {
			fresh, e := inspect(g.Path)
			if e == nil && fresh.SHA256 == g.SHA256 {
				apps = append(apps, g.Path)
			}
		}
	}
	host := sharedHostLUID.Load()
	if host != 0 && m.links[host] == nil {
		return nil, fmt.Errorf("network-only shared host not admitted")
	}
	specs, e := IPadNetworkOnlyPolicy(luid, host, apps)
	if e != nil {
		return nil, e
	}
	sub, e := randomGUID()
	if e != nil {
		return nil, e
	}
	keys := make([]windows.GUID, len(specs))
	names := make([]string, len(specs))
	for i := range specs {
		keys[i], e = randomGUID()
		if e != nil {
			return nil, e
		}
		names[i] = keys[i].String()
	}
	if len(m.conf.Journals) >= 32 {
		return nil, fmt.Errorf("network-only gateway journal limit")
	}
	m.conf.Journals = append(m.conf.Journals, journal{sub.String(), luid, names})
	if e := m.save(); e != nil {
		m.conf.Journals = m.conf.Journals[:len(m.conf.Journals)-1]
		return nil, e
	}
	e = commitThenVerify(func() error {
		return transaction(m.engine, func() error {
			if e := addSublayer(m.engine, sub); e != nil {
				return e
			}
			for i, s := range specs {
				if _, e := addFilter(m.engine, keys[i], sub, s); e != nil {
					return e
				}
			}
			return nil
		})
	}, func() error {
		for i, s := range specs {
			if e := verifyFilter(m.engine, keys[i], sub, s); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		if cleanup := m.removeOwned(sub, names); cleanup != nil {
			return nil, fmt.Errorf("%w; network-only cleanup pending: %v", e, cleanup)
		}
		m.conf.Journals = m.conf.Journals[:len(m.conf.Journals)-1]
		if saveErr := m.save(); saveErr != nil {
			return nil, fmt.Errorf("%w; cleanup receipt pending: %v", e, saveErr)
		}
		return nil, e
	}
	m.networkOnlyActive++
	group := &networkOnlyFilterGroup{Sub: sub, Child: luid, Host: host, Keys: names, Apps: map[string]bool{}}
	for _, path := range apps {
		group.Apps[strings.ToLower(path)] = true
	}
	if m.networkOnlyGroups == nil {
		m.networkOnlyGroups = map[string]*networkOnlyFilterGroup{}
	}
	m.networkOnlyGroups[sub.String()] = group
	var once sync.Once
	var stopErr error
	return func() error {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if stopErr = m.removeOwned(sub, group.Keys); stopErr != nil {
				m.problem = stopErr.Error()
				return
			}
			m.networkOnlyActive--
			delete(m.networkOnlyGroups, sub.String())
			next := []journal{}
			for _, j := range m.conf.Journals {
				if j.Sublayer != sub.String() {
					next = append(next, j)
				}
			}
			m.conf.Journals = next
			stopErr = m.save()
			if stopErr != nil {
				m.problem = stopErr.Error()
			}
		})
		return stopErr
	}, nil
}

type networkOnlyFilterGroup struct {
	Sub         windows.GUID
	Child, Host uint64
	Keys        []string
	Apps        map[string]bool
}

// Saved application choices remain usable on Mac. Before granting a newly
// admitted Apple executable, install iPad-only hard blocks in each active group.
func (m *Manager) ensureNetworkOnlyAppBlocks(path string) error {
	for _, group := range m.networkOnlyGroups {
		if group.Apps[strings.ToLower(path)] {
			continue
		}
		all, e := IPadNetworkOnlyPolicy(group.Child, group.Host, []string{path})
		if e != nil {
			return e
		}
		specs := []Specification{}
		for _, s := range all {
			if s.Application != "" {
				specs = append(specs, s)
			}
		}
		names := make([]string, len(specs))
		keys := make([]windows.GUID, len(specs))
		for i := range specs {
			keys[i], e = randomGUID()
			if e != nil {
				return e
			}
			names[i] = keys[i].String()
		}
		found := false
		for i := range m.conf.Journals {
			if m.conf.Journals[i].Sublayer == group.Sub.String() {
				if len(m.conf.Journals[i].Keys)+len(names) > 2048 {
					return fmt.Errorf("network-only filter journal limit")
				}
				m.conf.Journals[i].Keys = append(m.conf.Journals[i].Keys, names...)
				found = true
			}
		}
		if !found {
			return fmt.Errorf("network-only filter journal missing")
		}
		// Keep new keys in the cleanup closure even if save or native add fails.
		group.Keys = append(group.Keys, names...)
		if e := m.save(); e != nil {
			return e
		}
		e = commitThenVerify(func() error {
			return transaction(m.engine, func() error {
				for i, s := range specs {
					if _, e := addFilter(m.engine, keys[i], group.Sub, s); e != nil {
						return e
					}
				}
				return nil
			})
		}, func() error {
			for i, s := range specs {
				if e := verifyFilter(m.engine, keys[i], group.Sub, s); e != nil {
					return e
				}
			}
			return nil
		})
		if e != nil {
			return e
		}
		group.Apps[strings.ToLower(path)] = true
	}
	return nil
}
