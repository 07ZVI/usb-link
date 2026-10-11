//go:build windows && amd64

package netconfig

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
)

func CaptureSharedHostHealthyNative(index uint32, luid uint64) (string, error) {
	t, _, e := openVerifiedNativeHost(index)
	if e != nil {
		return "", e
	}
	defer t.set.Close()
	if luid == 0 || t.network.LUID != luid {
		return "", fmt.Errorf("USB_HOST_NATIVE_MAPPING_CHANGED")
	}
	if e = VerifySharedHostRecreatedNative(index, luid, t.node.Instance); e != nil {
		return "", e
	}
	return t.node.Instance, nil
}

// CaptureSharedHostNonpresentNative exposes an exact instance only to the
// protected local recovery transaction. It is not a diagnostic authorization
// and accepts no arbitrary instance or GUID selector.
func CaptureSharedHostNonpresentNative(index uint32, luid uint64) (string, error) {
	t, _, e := openVerifiedNonpresentNativeHost(index)
	if e != nil {
		return "", e
	}
	defer t.set.Close()
	if luid == 0 || t.network.LUID != luid {
		return "", fmt.Errorf("USB_HOST_NATIVE_MAPPING_CHANGED")
	}
	if e = nativeHostIPv4Absent(t.network); e != nil {
		return "", e
	}
	p, e := t.set.DeviceInstallParams(t.info)
	if e != nil || p.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0 {
		return "", fmt.Errorf("USB_HOST_NATIVE_RECREATE_FLAGS_UNPROVEN")
	}
	return t.node.Instance, nil
}

// Closing may need to finish deletion of the one original owned address after
// a crash. It does not authorize Create and deliberately does not require
// address absence; usbhost proves the complete address set separately.
func CaptureSharedHostClosingNative(index uint32, luid uint64) (string, bool, error) {
	instance, e := CaptureSharedHostHealthyNative(index, luid)
	if e == nil {
		return instance, false, nil
	}
	if e.Error() != "USB_HOST_NATIVE_PNP_BINDING_NOT_UNIQUE" {
		return "", false, e
	}
	t, _, e := openVerifiedNonpresentNativeHost(index)
	if e != nil {
		return "", false, e
	}
	defer t.set.Close()
	if luid == 0 || t.network.LUID != luid {
		return "", false, fmt.Errorf("USB_HOST_NATIVE_MAPPING_CHANGED")
	}
	p, e := t.set.DeviceInstallParams(t.info)
	if e != nil || p.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0 {
		return "", false, fmt.Errorf("USB_HOST_NATIVE_RECREATE_FLAGS_UNPROVEN")
	}
	return t.node.Instance, true, nil
}

// VerifySharedHostRecreatedNative correlates the actual returned handle's LUID
// with a unique healthy native node and a complete installed-node enumeration.
// The instance is the protected pre-call identity, never an RPC argument.
func VerifySharedHostRecreatedNative(index uint32, luid uint64, instance string) error {
	t, _, e := openVerifiedNativeHost(index)
	if e != nil {
		return e
	}
	defer t.set.Close()
	if luid == 0 || t.network.LUID != luid || t.node.Instance != instance {
		return fmt.Errorf("USB_HOST_NATIVE_RECREATE_IDENTITY_CHANGED")
	}
	p, e := t.set.DeviceInstallParams(t.info)
	if e != nil || p.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0 {
		return fmt.Errorf("USB_HOST_NATIVE_RECREATE_FLAGS_UNPROVEN")
	}
	class, _ := windows.GUIDFromString(hostNetClass)
	set, e := windows.SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")
	if e != nil {
		return fmt.Errorf("USB_HOST_NATIVE_RECREATE_ENUMERATION_UNPROVEN")
	}
	defer set.Close()
	matches := 0
	for i := 0; i < 4096; i++ {
		info, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			if matches != 1 {
				return fmt.Errorf("USB_HOST_NATIVE_RECREATE_BINDING_NOT_UNIQUE")
			}
			fresh, _, err := readNativeHostInterface(index)
			if err != nil || fresh != t.network {
				return fmt.Errorf("USB_HOST_NATIVE_MAPPING_CHANGED")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("USB_HOST_NATIVE_RECREATE_ENUMERATION_UNPROVEN")
		}
		key, err := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if err != nil {
			return fmt.Errorf("USB_HOST_NATIVE_RECREATE_BINDING_UNREADABLE")
		}
		guid, found, err := nativeHostRegistryGUID(key)
		windows.RegCloseKey(key)
		if err != nil {
			return err
		}
		if !found || !strings.EqualFold(guid, usbaddress.HostGUID) {
			continue
		}
		matches++
		n, err := readNativeHostNode(set, info, guid)
		if err != nil || n != t.node {
			return fmt.Errorf("USB_HOST_NATIVE_RECREATE_IDENTITY_CHANGED")
		}
	}
	return fmt.Errorf("USB_HOST_NATIVE_RECREATE_ENUMERATION_LIMIT")
}
