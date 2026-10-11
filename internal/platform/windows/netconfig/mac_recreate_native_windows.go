//go:build windows && amd64

package netconfig

import (
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
)

const retainedMacGUID = "{A4611646-E050-4D25-B83E-633A5598F302}"

// CaptureOwnedMacNative is local-only. The caller must separately prove the
// protected factory original/current binding and current USB consent. It does
// not create, remove, open an adapter or authorize an address/rule.
func CaptureOwnedMacNative(index uint32, luid uint64, nonpresent bool) (string, error) {
	t, e := openVerifiedMacLifecycle(index, luid, nonpresent)
	if e != nil {
		return "", e
	}
	defer t.set.Close()
	return t.node.Instance, nil
}
func openVerifiedMacLifecycle(index uint32, luid uint64, nonpresent bool) (*nativeHostTarget, error) {
	var first *nativeHostTarget
	for pass := 0; pass < 2; pass++ {
		f, _, e := readNativeWintunInterface(index, retainedMacGUID, "USB Link")
		if e != nil || f.LUID != luid || luid == 0 {
			if first != nil {
				first.set.Close()
			}
			return nil, errors.New("USB_MAC_RECREATE_MAPPING_UNPROVEN")
		}
		t, _, e := enumerateNativeHostRemovalNode(f, nonpresent)
		if e != nil {
			if first != nil {
				first.set.Close()
			}
			return nil, e
		}
		reject := func() (*nativeHostTarget, error) {
			t.set.Close()
			if first != nil {
				first.set.Close()
			}
			return nil, errors.New("USB_MAC_RECREATE_NODE_CHANGED")
		}
		flags, e := t.set.DeviceInstallParams(t.info)
		if e != nil || flags.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0 {
			return reject()
		}
		if nonpresent {
			if t.nonpresent == nil || validateNativeWintunNonpresent(t.node, *t.nonpresent, retainedMacGUID) != nil || nativeHostIPv4Absent(f) != nil {
				return reject()
			}
		} else if validateNativeWintunNodeForGUID(t.node, retainedMacGUID) != nil {
			return reject()
		}
		if first != nil {
			if first.network != t.network || first.node != t.node || (nonpresent && *first.nonpresent != *t.nonpresent) {
				return reject()
			}
			first.set.Close()
			return t, nil
		}
		first = t
	}
	return nil, errors.New("USB_MAC_RECREATE_NODE_UNPROVEN")
}
func VerifyOwnedMacRecreatedNative(index uint32, luid uint64, instance string) error {
	if instance == "" || strings.ContainsAny(instance, "*?\x00") {
		return errors.New("USB_MAC_RECREATE_INSTANCE_UNPROVEN")
	}
	t, e := openVerifiedMacLifecycle(index, luid, false)
	if e != nil {
		return e
	}
	defer t.set.Close()
	if t.node.Instance != instance {
		return errors.New("USB_MAC_RECREATE_INSTANCE_CHANGED")
	}
	// PRESENT uniqueness alone cannot hide a second installed ghost.
	class, _ := windows.GUIDFromString(hostNetClass)
	set, e := windows.SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")
	if e != nil {
		return errors.New("USB_MAC_RECREATE_INSTALLED_UNREADABLE")
	}
	defer set.Close()
	count := 0
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			if count == 1 {
				return nil
			}
			return errors.New("USB_MAC_RECREATE_INSTALLED_NOT_UNIQUE")
		}
		if e != nil {
			return errors.New("USB_MAC_RECREATE_INSTALLED_UNREADABLE")
		}
		key, e := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if e == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if e != nil {
			return errors.New("USB_MAC_RECREATE_INSTALLED_UNREADABLE")
		}
		g, present, e := nativeHostRegistryGUID(key)
		windows.RegCloseKey(key)
		if e != nil {
			return e
		}
		if !present || !strings.EqualFold(g, retainedMacGUID) {
			continue
		}
		count++
		node, e := readNativeWintunNodeForGUID(set, info, g, retainedMacGUID)
		if e != nil || node != t.node {
			return errors.New("USB_MAC_RECREATE_INSTALLED_CHANGED")
		}
	}
	return errors.New("USB_MAC_RECREATE_INSTALLED_LIMIT")
}

// VerifyOwnedMacFactorySourceNative accepts only an exact typed phantom with
// no IPv4, or full MIB+installed-NET+ALLCLASSES absence of the protected instance.
// CR13 by itself is never absence. No failed/foreign node is ignored.
func VerifyOwnedMacFactorySourceNative(index uint32, luid uint64, instance string) error {
	return verifyOwnedWintunFactorySourceNative(index, luid, instance, retainedMacGUID, "USB Link")
}

// VerifySharedHostFactorySourceNative proves only a protected pre-call source.
// It never authorizes adopting a newly healthy mapping or creates an adapter.
func VerifySharedHostFactorySourceNative(index uint32, luid uint64, instance string) error {
	e := verifyOwnedWintunFactorySourceNative(index, luid, instance, usbaddress.HostGUID, usbaddress.HostName)
	if e != nil {
		return errors.New(strings.ReplaceAll(e.Error(), "USB_MAC_RECREATE_", "USB_HOST_RECREATE_"))
	}
	return nil
}

func verifyOwnedWintunFactorySourceNative(index uint32, luid uint64, instance, guid, alias string) error {
	if instance == "" || strings.ContainsAny(instance, "*?\x00") || index == 0 || luid == 0 {
		return errors.New("USB_MAC_RECREATE_SOURCE_INVALID")
	}
	// A historical index can be reused. Project only the immutable saved
	// LUID through fresh NetIO; never persist/adopt this projected scope.
	r := windows.MibIfRow2{InterfaceLuid: luid}
	projected := index
	if e := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r); e == nil {
		if r.InterfaceLuid != luid || !strings.EqualFold(r.InterfaceGuid.String(), guid) || windows.UTF16ToString(r.Alias[:]) != alias || r.Type != 53 || r.InterfaceIndex == 0 {
			return errors.New("USB_MAC_RECREATE_SOURCE_MAPPING_CHANGED")
		}
		projected = r.InterfaceIndex
	} else if e != windows.ERROR_NOT_FOUND && e != windows.ERROR_FILE_NOT_FOUND {
		return errors.New("USB_MAC_RECREATE_SOURCE_MAPPING_UNREADABLE")
	}
	var got string
	var e error
	if strings.EqualFold(guid, retainedMacGUID) {
		got, e = CaptureOwnedMacNative(projected, luid, true)
	} else {
		got, e = CaptureSharedHostNonpresentNative(projected, luid)
	}
	if e == nil {
		if got == instance {
			return nil
		}
		return errors.New("USB_MAC_RECREATE_INSTANCE_CHANGED")
	}
	absent, ae := nativeWintunRemovalAbsent(instance, guid, alias)
	if ae != nil || !absent {
		return errors.New("USB_MAC_RECREATE_SOURCE_UNPROVEN")
	}
	if e = nativeHostIPv4Absent(nativeHostInterface{Index: 0, LUID: luid}); e != nil {
		return e
	}
	return nil
}
