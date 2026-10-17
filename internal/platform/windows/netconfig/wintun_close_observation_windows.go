//go:build windows && amd64

package netconfig

import (
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

func observeOwnedMacCloseNative(luid uint64, instance string) (wintunCloseObservation, error) {
	var matches wintunCloseMatches
	s, err := collectWintunCloseObservation(func() (uint32, bool, error) {
		var table *windows.MibIfTable2
		if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table) != nil || table == nil {
			return 0, false, errors.New("USB_MAC_CLOSE_INTERFACE_QUERY_FAILED")
		}
		defer windows.FreeMibTable(unsafe.Pointer(table))
		if table.NumEntries > 65536 {
			return 0, false, errors.New("USB_MAC_CLOSE_INTERFACE_LIMIT")
		}
		present := false
		for _, row := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
			match := wintunCloseMatch{OldLUID: row.InterfaceLuid == luid, GUID: strings.EqualFold(row.InterfaceGuid.String(), NativeMacGUID), Alias: windows.UTF16ToString(row.Alias[:]) == "USB Link", Oper: uint32(row.OperStatus), Admin: uint32(row.AdminStatus), Media: uint32(row.MediaConnectState), Flags: row.InterfaceAndOperStatusFlags}
			if match.OldLUID || match.GUID || match.Alias {
				present = true
				matches.record(match)
			}
		}
		return table.NumEntries, present, nil
	}, func() (uint32, bool, error) {
		var table *windows.MibUnicastIpAddressTable
		if windows.GetUnicastIpAddressTable(windows.AF_INET, &table) != nil || table == nil {
			return 0, false, errors.New("USB_MAC_CLOSE_IPV4_QUERY_FAILED")
		}
		defer windows.FreeMibTable(unsafe.Pointer(table))
		if table.NumEntries > 65536 {
			return 0, false, errors.New("USB_MAC_CLOSE_IPV4_LIMIT")
		}
		present := false
		for _, row := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
			// Index reuse by another adapter is not the old creator's address.
			if row.InterfaceLuid == luid {
				present = true
			}
		}
		return table.NumEntries, present, nil
	}, func() (uint32, bool, error) {
		class, _ := windows.GUIDFromString(hostNetClass)
		set, err := windows.SetupDiGetClassDevsEx(&class, "", 0, windows.DIGCF_PRESENT, 0, "")
		if err != nil {
			return 0, false, errors.New("USB_MAC_CLOSE_PRESENT_NET_QUERY_FAILED")
		}
		defer set.Close()
		present := false
		for i := uint32(0); i < 4096; i++ {
			info, err := set.EnumDeviceInfo(int(i))
			if err == windows.ERROR_NO_MORE_ITEMS {
				return i, present, nil
			}
			if err != nil {
				return i, present, errors.New("USB_MAC_CLOSE_PRESENT_NET_QUERY_FAILED")
			}
			key, err := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
			if err == windows.ERROR_FILE_NOT_FOUND {
				continue
			}
			if err != nil {
				return i, present, errors.New("USB_MAC_CLOSE_PRESENT_NET_BINDING_UNREADABLE")
			}
			guid, found, err := nativeHostRegistryGUID(key)
			windows.RegCloseKey(key)
			if err != nil {
				return i, present, errors.New("USB_MAC_CLOSE_PRESENT_NET_BINDING_UNREADABLE")
			}
			if found && strings.EqualFold(guid, NativeMacGUID) {
				present = true
			}
		}
		return 4096, present, errors.New("USB_MAC_CLOSE_PRESENT_NET_LIMIT")
	}, func() (uint32, bool, error) {
		set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
		if err != nil {
			return 0, false, errors.New("USB_MAC_CLOSE_PRESENT_INSTANCE_QUERY_FAILED")
		}
		defer set.Close()
		present := false
		for i := uint32(0); i < 65536; i++ {
			info, err := set.EnumDeviceInfo(int(i))
			if err == windows.ERROR_NO_MORE_ITEMS {
				return i, present, nil
			}
			if err != nil {
				return i, present, errors.New("USB_MAC_CLOSE_PRESENT_INSTANCE_QUERY_FAILED")
			}
			id, err := set.DeviceInstanceID(info)
			if err != nil {
				return i, present, errors.New("USB_MAC_CLOSE_PRESENT_INSTANCE_ID_UNREADABLE")
			}
			if strings.EqualFold(id, instance) {
				present = true
			}
		}
		return 65536, present, errors.New("USB_MAC_CLOSE_PRESENT_INSTANCE_LIMIT")
	})
	s.Matches = matches
	return s, err
}
