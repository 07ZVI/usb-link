//go:build windows && amd64

package usbgateway

import (
	"fmt"
	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/transport/routing"
	"unsafe"
)

// Internet permits live in the existing USB sublayer. A soft permit in another
// sublayer could not override the existing terminating USB forward block.
func (m *Manager) OpenInternet(upstream uint64, excluded []string) (func() error, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if upstream == 0 {
		return nil, fmt.Errorf("INTERNET_UPSTREAM_INVALID")
	}
	type owned struct {
		a    *attachment
		key  windows.GUID
		spec Specification
	}
	var added []owned
	prefixes := routing.PublicPrefixes(excluded)
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("INTERNET_NO_PUBLIC_DESTINATIONS")
	}
	for luid, a := range m.links {
		if luid != sharedHostLUID.Load() && a.peer != "10.6.9.2" {
			continue
		}
		if luid == upstream {
			return nil, fmt.Errorf("INTERNET_USB_UPSTREAM_REJECTED")
		}
		if len(a.keys)+2*len(prefixes) > 2048 {
			return nil, fmt.Errorf("INTERNET_GATEWAY_RULE_LIMIT")
		}
		for _, public := range prefixes {
			for _, reverse := range []bool{false, true} {
				field, src, dst := localInterface, "10.6.9.2/32", public.String()
				if reverse {
					field, src, dst = forwardInterface, public.String(), "10.6.9.2/32"
				}
				spec := Specification{Layer: forwardingLayers[0], InterfaceField: field, LUID: luid, Permit: true, InternetForward: true, OtherLUID: upstream, ForwardSource: src, ForwardDestination: dst}
				key, e := randomGUID()
				if e != nil {
					return nil, e
				}
				added = append(added, owned{a, key, spec})
			}
		}
	}
	if len(added) == 0 {
		return nil, fmt.Errorf("INTERNET_USB_GATEWAY_NOT_ATTACHED")
	}
	// Journal each key before mutation. Existing detach/recovery owns the same
	// keys even after a crash between installation and the cleanup callback.
	for _, o := range added {
		found := false
		for i := range m.conf.Journals {
			j := &m.conf.Journals[i]
			if j.Sublayer == o.a.sub.String() {
				j.Keys = append(j.Keys, o.key.String())
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("INTERNET_GATEWAY_JOURNAL_MISSING")
		}
		o.a.keys = append(o.a.keys, o.key)
	}
	if e := m.save(); e != nil {
		return nil, e
	}
	cleanup := func() error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if e := transaction(m.engine, func() error {
			for _, o := range added {
				e := call("FwpmFilterDeleteByKey0", m.engine, uintptr(unsafe.Pointer(&o.key)))
				if e != nil && !filterAbsent(e) {
					return e
				}
			}
			return nil
		}); e != nil {
			return e
		}
		remove := map[string]bool{}
		for _, o := range added {
			remove[o.key.String()] = true
		}
		for _, a := range m.links {
			next := []windows.GUID{}
			for _, k := range a.keys {
				if !remove[k.String()] {
					next = append(next, k)
				}
			}
			a.keys = next
		}
		for i := range m.conf.Journals {
			j := &m.conf.Journals[i]
			next := []string{}
			for _, k := range j.Keys {
				if !remove[k] {
					next = append(next, k)
				}
			}
			j.Keys = next
		}
		return m.save()
	}
	e := transaction(m.engine, func() error {
		for _, o := range added {
			if _, e := addFilter(m.engine, o.key, o.a.sub, o.spec); e != nil {
				return e
			}
		}
		return nil
	})
	if e == nil {
		for _, o := range added {
			if e = verifyFilter(m.engine, o.key, o.a.sub, o.spec); e != nil {
				break
			}
		}
	}
	return cleanup, e
}
func filterAbsent(err error) bool {
	if e, ok := err.(*wfpError); ok {
		return e.Code == 0x80320003
	}
	return false
}
