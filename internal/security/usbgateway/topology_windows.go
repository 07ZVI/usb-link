//go:build windows && amd64

package usbgateway

import (
	"fmt"
	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/transport/usbaddress"
)

func (m *Manager) OwnedInterfaces() ([]usbaddress.InterfaceProof, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	proofs := []usbaddress.InterfaceProof{}
	for luid := range m.links {
		r := windows.MibIfRow2{InterfaceLuid: luid}
		if e := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r); e != nil {
			return nil, fmt.Errorf("owned USB interface unavailable: %w", e)
		}
		if luid == sharedHostLUID.Load() {
			continue
		}
		proofs = append(proofs, usbaddress.InterfaceProof{Index: r.InterfaceIndex, GUID: r.InterfaceGuid.String(), LUID: luid})
	}
	return proofs, nil
}

func NativeSMBScopes() ([]struct{ GUID, Peer string }, error) {
	current.Lock()
	m := current.m
	current.Unlock()
	out := []struct{ GUID, Peer string }{}
	if m == nil {
		return out, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for luid, a := range m.links {
		r := windows.MibIfRow2{InterfaceLuid: luid}
		if e := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r); e != nil {
			return nil, e
		}
		peers := []string{a.peer}
		if luid == sharedHostLUID.Load() {
			peers = []string{"10.6.9.2", "10.6.9.3"}
		}
		for _, p := range peers {
			if p == "10.6.9.2" || p == "10.6.9.3" {
				out = append(out, struct{ GUID, Peer string }{r.InterfaceGuid.String(), p})
			}
		}
	}
	return out, nil
}
