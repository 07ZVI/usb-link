package usbhost

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/transport/usbaddress"
)

type journal struct {
	Version          int
	GUID             string
	Index            uint32
	LUID             uint64
	Planned, Created int64
	Token            string
	AddressMode      string `json:",omitempty"`
	PersistentSHA256 string `json:",omitempty"`
}

type hostIdentity struct {
	GUID, Alias string
	Type        uint32
	Index       uint32
	LUID        uint64
}

func validateHostCandidates(candidates []hostIdentity) error {
	if len(candidates) > 1 {
		return fmt.Errorf("USB_HOST_INTERFACE_AMBIGUOUS")
	}
	if len(candidates) == 0 {
		return nil
	}
	c := candidates[0]
	if !strings.EqualFold(c.GUID, usbaddress.HostGUID) || c.Alias != usbaddress.HostName || c.Type != 53 || c.Index == 0 || c.LUID == 0 {
		return fmt.Errorf("USB_HOST_FOREIGN_IDENTITY")
	}
	return nil
}

func decodeJournal(b []byte) (journal, error) {
	var p journal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > 2048 || d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || (p.Version != 1 && p.Version != 2) || p.GUID != usbaddress.HostGUID || p.Planned <= 0 || p.Created < 0 || len(p.Token) != 24 || (p.Index == 0) != (p.LUID == 0) || (p.Created != 0 && p.Index == 0) {
		return journal{}, fmt.Errorf("USB_HOST_JOURNAL_INVALID")
	}
	if (p.Version == 1 && (p.AddressMode != "" || p.PersistentSHA256 != "")) || (p.Version == 2 && (p.Created <= 0 || (p.AddressMode != "legacy" && p.AddressMode != "persistent") || len(p.PersistentSHA256) != 64)) {
		return journal{}, fmt.Errorf("USB_HOST_JOURNAL_INVALID")
	}
	if p.Version == 2 {
		if !exactJSONFields(b, []string{"Version", "GUID", "Index", "LUID", "Planned", "Created", "Token", "AddressMode", "PersistentSHA256"}) {
			return journal{}, fmt.Errorf("USB_HOST_JOURNAL_INVALID")
		}
		if _, e := hex.DecodeString(p.PersistentSHA256); e != nil {
			return journal{}, fmt.Errorf("USB_HOST_JOURNAL_INVALID")
		}
	}
	if _, e := hex.DecodeString(p.Token); e != nil {
		return journal{}, fmt.Errorf("USB_HOST_JOURNAL_INVALID")
	}
	return p, nil
}

// The identity is independently checked by the native interface table and the
// pinned Wintun/net-class readback. Only the boot-local mapping may change.
type recoveryAddress struct {
	Index                            uint32
	LUID                             uint64
	Address                          [4]byte
	Prefix                           uint8
	PrefixOrigin, SuffixOrigin       uint32
	ValidLifetime, PreferredLifetime uint32
	Created                          int64
}

func validateNonpresentRecoveryOwnership(p journal, luid uint64, addressCount int) error {
	if p.Created <= 0 || p.Index == 0 || p.LUID == 0 || luid != p.LUID || addressCount != 0 {
		return fmt.Errorf("USB_HOST_NONPRESENT_OWNERSHIP_UNPROVEN")
	}
	return nil
}

func rebindRecovery(p journal, index uint32, luid uint64, addresses []recoveryAddress) (journal, string, error) {
	if index == 0 || luid == 0 {
		return journal{}, "unproven", fmt.Errorf("USB_HOST_MAPPING_UNPROVEN")
	}
	next := p
	next.Index, next.LUID = index, luid
	state := "absent"
	for _, a := range addresses {
		if a.LUID != luid || a.Index != index || a.Address != [4]byte{10, 6, 9, 1} {
			return journal{}, "foreign", fmt.Errorf("USB_HOST_FOREIGN_IPV4_ADDRESS")
		}
		if state != "absent" {
			return journal{}, "ambiguous", fmt.Errorf("USB_HOST_ADDRESS_AMBIGUOUS")
		}
		if p.Index == 0 {
			return journal{}, "unexpected", fmt.Errorf("USB_HOST_INTENT_ADDRESS_UNEXPECTED")
		}
		ownedStamp := p.Created != 0 && a.Created == p.Created || p.Created == 0 && a.Created >= p.Planned && a.Created-p.Planned <= 150000000
		if a.Prefix != 32 || a.PrefixOrigin != 1 || a.SuffixOrigin != 1 || a.ValidLifetime > 3600 || a.PreferredLifetime > 3600 || !ownedStamp {
			return journal{}, "unowned", fmt.Errorf("USB_HOST_ADDRESS_OWNERSHIP_CHANGED")
		}
		state = "owned"
	}
	return next, state, nil
}

func checkpointMapping(old, next journal, write func(journal) error, read func() ([]byte, error)) error {
	if old == next {
		return nil
	}
	if e := write(next); e != nil {
		return e
	}
	b, e := read()
	if e != nil {
		return fmt.Errorf("USB_HOST_MAPPING_READBACK_FAILED")
	}
	p, e := decodeJournal(b)
	if e != nil || p != next {
		return fmt.Errorf("USB_HOST_MAPPING_READBACK_FAILED")
	}
	return nil
}

func planPersistentHostMapping(old journal, first, last interfaceconfig.ActiveOwnership) (journal, error) {
	if old.Version != 1 && old.Version != 2 {
		return journal{}, fmt.Errorf("USB_HOST_PERSISTENT_JOURNAL_UNPROVEN")
	}
	if last.AddressMode != "legacy" && last.AddressMode != "persistent" {
		return journal{}, fmt.Errorf("USB_HOST_PERSISTENT_MODE_UNPROVEN")
	}
	if old.Version == 2 && old.PersistentSHA256 != last.ReceiptSHA256 {
		return journal{}, fmt.Errorf("USB_HOST_PERSISTENT_RECEIPT_CHANGED")
	}
	proof, e := interfaceconfig.PlanOwnedPersistentRebind(interfaceconfig.Scope{Role: "host", GUID: old.GUID, Index: old.Index, LUID: old.LUID}, old.Created, first, last)
	if e != nil {
		return journal{}, e
	}
	if proof.AddressMode == "legacy" && proof.Created != old.Created {
		return journal{}, fmt.Errorf("USB_HOST_LEGACY_STAMP_CHANGED")
	}
	next := old
	next.Version = 2
	next.Index = proof.Scope.Index
	next.LUID = proof.Scope.LUID
	next.Created = proof.Created
	next.AddressMode = proof.AddressMode
	next.PersistentSHA256 = proof.ReceiptSHA256
	return next, nil
}
