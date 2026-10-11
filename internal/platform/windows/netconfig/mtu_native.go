package netconfig

import (
	"errors"
	"strings"
)

type macMTUIdentity struct {
	Index uint32
	LUID  uint64
	GUID  string
	Alias string
	Type  uint32
}

func validateVerifiedMacMTUScope(index uint32, guid string, luid uint64, mtu int) error {
	if index == 0 || luid == 0 || !guidPattern.MatchString(guid) || (mtu != 1500 && mtu != 9000 && mtu != 16000) {
		return errors.New("USB_MAC_MTU_SCOPE_INVALID")
	}
	return nil
}

func validateVerifiedMacMTUIdentity(rows []macMTUIdentity, index uint32, guid string, luid uint64) error {
	count := 0
	for _, row := range rows {
		if row.Index == index || row.LUID == luid || strings.EqualFold(row.GUID, guid) || row.Alias == "USB Link" {
			count++
			if row.Index != index || row.LUID != luid || !strings.EqualFold(row.GUID, guid) || row.Alias != "USB Link" || row.Type != 53 {
				return errors.New("USB_MAC_MTU_INTERFACE_CHANGED")
			}
		}
	}
	if count != 1 {
		return errors.New("USB_MAC_MTU_INTERFACE_AMBIGUOUS_OR_ABSENT")
	}
	return nil
}
