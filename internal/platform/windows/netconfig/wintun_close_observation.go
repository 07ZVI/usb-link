package netconfig

import (
	"errors"
	"strings"
)

// Closing a held creator ends its live network object. It does not promise to
// uninstall nonpresent PnP records or authorize their later reuse/removal.
type wintunCloseObservation struct {
	InterfacesRead       bool               `json:"interfaces_read"`
	IPv4Read             bool               `json:"ipv4_read"`
	PresentNetRead       bool               `json:"present_net_read"`
	PresentInstancesRead bool               `json:"present_instances_read"`
	InterfacePresent     bool               `json:"interface_present"`
	IPv4Present          bool               `json:"ipv4_present"`
	NetBindingPresent    bool               `json:"net_binding_present"`
	ExactInstancePresent bool               `json:"exact_instance_present"`
	InterfaceRows        uint32             `json:"interface_rows"`
	IPv4Rows             uint32             `json:"ipv4_rows"`
	PresentNetNodes      uint32             `json:"present_net_nodes"`
	PresentInstances     uint32             `json:"present_instances"`
	Matches              wintunCloseMatches `json:"interface_matches"`
}

// Only relationships to the private close target and native scalar state are
// retained. These diagnostics never decide whether a row is harmless.
type wintunCloseMatch struct {
	OldLUID bool   `json:"old_luid"`
	GUID    bool   `json:"guid"`
	Alias   bool   `json:"alias"`
	Oper    uint32 `json:"oper"`
	Admin   uint32 `json:"admin"`
	Media   uint32 `json:"media"`
	Flags   uint8  `json:"flags"`
}
type wintunCloseMatches struct {
	Rows    [4]wintunCloseMatch `json:"rows"`
	Count   uint32              `json:"count"`
	Omitted uint32              `json:"omitted"`
}

func (m *wintunCloseMatches) record(row wintunCloseMatch) {
	if !row.OldLUID && !row.GUID && !row.Alias {
		return
	}
	if m.Count == uint32(len(m.Rows)) {
		m.Omitted++
		return
	}
	m.Rows[m.Count] = row
	m.Count++
}

func wintunCloseScopeValid(index uint32, luid uint64, instance string) bool {
	return index != 0 && luid != 0 && instance != "" && len(instance) <= 1024 && !strings.ContainsAny(instance, "*?\x00")
}

func (s wintunCloseObservation) absent() bool {
	return s.InterfacesRead && s.IPv4Read && s.PresentNetRead && s.PresentInstancesRead && !s.InterfacePresent && !s.IPv4Present && !s.NetBindingPresent && !s.ExactInstancePresent
}

func (s wintunCloseObservation) closeResult(readErr error) (absent, parentRecoveryRequired bool, err error) {
	if readErr != nil {
		return false, false, readErr
	}
	if s.InterfacesRead && s.IPv4Read && s.PresentNetRead && s.PresentInstancesRead && s.InterfacePresent && !s.IPv4Present && !s.NetBindingPresent && !s.ExactInstancePresent {
		// Do not certify this MIB row as absent/down/harmless. End the creator
		// with its journal unclean so the parent can recover after process exit.
		return false, true, errors.New("USB_MAC_LIFETIME_CLOSE_ABSENCE_UNCONFIRMED")
	}
	return s.absent(), false, nil
}

type wintunCloseRead func() (rows uint32, present bool, err error)

func collectWintunCloseObservation(interfaces, ipv4, net, instances wintunCloseRead) (s wintunCloseObservation, err error) {
	s.InterfaceRows, s.InterfacePresent, err = interfaces()
	if err != nil {
		return
	}
	s.InterfacesRead = true
	s.IPv4Rows, s.IPv4Present, err = ipv4()
	if err != nil {
		return
	}
	s.IPv4Read = true
	s.PresentNetNodes, s.NetBindingPresent, err = net()
	if err != nil {
		return
	}
	s.PresentNetRead = true
	s.PresentInstances, s.ExactInstancePresent, err = instances()
	if err != nil {
		return
	}
	s.PresentInstancesRead = true
	return
}
