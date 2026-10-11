//go:build windows && amd64

package netconfig

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"time"
	"unsafe"
)

type SharedHostRemovalResult struct{ Attempted, FlagsReadable, RestartRequired, AbsenceVerified bool }

func nativeHostIPv4Absent(f nativeHostInterface) error {
	var table *windows.MibUnicastIpAddressTable
	if windows.GetUnicastIpAddressTable(windows.AF_INET, &table) != nil || table == nil {
		return fmt.Errorf("USB_HOST_NATIVE_IPV4_QUERY_FAILED")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return fmt.Errorf("USB_HOST_NATIVE_IPV4_TABLE_INVALID")
	}
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if r.InterfaceLuid == f.LUID || (f.Index != 0 && r.InterfaceIndex == f.Index) {
			return fmt.Errorf("USB_HOST_IPV4_REMAINS_BEFORE_ADAPTER_REMOVAL")
		}
	}
	return nil
}

func nativeHostRemovalAbsent(instance string) (bool, error) {
	return nativeWintunRemovalAbsent(instance, usbaddress.HostGUID, usbaddress.HostName)
}
func nativeWintunRemovalAbsent(instance, guid, alias string) (bool, error) {
	if !((strings.EqualFold(guid, usbaddress.HostGUID) && alias == usbaddress.HostName) || (strings.EqualFold(guid, retainedMacGUID) && alias == "USB Link")) {
		return false, fmt.Errorf("USB_HOST_NATIVE_EXPECTED_GUID_INVALID")
	}
	var table *windows.MibIfTable2
	if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table) != nil || table == nil {
		return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_QUERY_FAILED")
	}
	if table.NumEntries > 65536 {
		windows.FreeMibTable(unsafe.Pointer(table))
		return false, fmt.Errorf("USB_HOST_NATIVE_INTERFACE_TABLE_INVALID")
	}
	present := false
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if strings.EqualFold(r.InterfaceGuid.String(), guid) || windows.UTF16ToString(r.Alias[:]) == alias {
			present = true
		}
	}
	windows.FreeMibTable(unsafe.Pointer(table))
	if present {
		return false, nil
	}
	class, _ := windows.GUIDFromString(hostNetClass)
	set, e := windows.SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")
	if e != nil {
		return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_QUERY_FAILED")
	}
	defer set.Close()
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			if instance == "" {
				return true, nil
			}
			return nativeHostExactInstanceAbsent(instance)
		}
		if e != nil {
			return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_QUERY_FAILED")
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_QUERY_FAILED")
		}
		if instance != "" && strings.EqualFold(id, instance) {
			return false, nil
		}
		key, err := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_BINDING_UNREADABLE")
		}
		bindingGUID, found, err := nativeHostRegistryGUID(key)
		windows.RegCloseKey(key)
		if err != nil {
			return false, err
		}
		if found && strings.EqualFold(bindingGUID, guid) {
			return false, nil
		}
	}
	return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_ENUMERATION_LIMIT")
}

// A changed class or nonpresent installation must not disguise the precise
// old instance as absent. Both completed and crash-resumed removal use this.
func nativeHostExactInstanceAbsent(instance string) (bool, error) {
	set, e := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_QUERY_FAILED")
	}
	defer set.Close()
	for i := 0; i < 65536; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			return true, nil
		}
		if e != nil {
			return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_QUERY_FAILED")
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_QUERY_FAILED")
		}
		if strings.EqualFold(id, instance) {
			return false, nil
		}
	}
	return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_ENUMERATION_LIMIT")
}

// RemoveVerifiedSharedHostNative is called only after the owner's durable
// journal and exact old address have been validated, removed and checkpointed
// by usbhost. A pre-DIF durable removal intent is required at that boundary.
// No RPC may call this API or supply a device instance. It always independently
// resolves the one fixed host and never deletes a driver package or USB root.
func RemoveVerifiedSharedHostNative(ctx context.Context, index uint32, luid uint64, durableIntent func(string) error) (SharedHostRemovalResult, error) {
	return removeVerifiedSharedHostNative(ctx, index, luid, durableIntent, false)
}

// This distinct route is available only to recovery of a completed protected
// journal with unchanged LUID and already absent IP rows. It never treats a
// nonpresent node as a healthy shared host.
func RemoveVerifiedNonpresentSharedHostNative(ctx context.Context, index uint32, luid uint64, durableIntent func(string) error) (SharedHostRemovalResult, error) {
	return removeVerifiedSharedHostNative(ctx, index, luid, durableIntent, true)
}

func removeVerifiedSharedHostNative(ctx context.Context, index uint32, luid uint64, durableIntent func(string) error, nonpresent bool) (out SharedHostRemovalResult, e error) {
	open := openVerifiedNativeHost
	if nonpresent {
		open = openVerifiedNonpresentNativeHost
	}
	if ctx.Err() != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVAL_CANCELLED")
	}
	t, _, e := open(index)
	if e != nil {
		return out, e
	}
	defer t.set.Close()
	if luid == 0 || t.network.LUID != luid {
		return out, fmt.Errorf("USB_HOST_NATIVE_MAPPING_CHANGED")
	}
	if e = nativeHostIPv4Absent(t.network); e != nil {
		return out, e
	}
	p, e := t.set.DeviceInstallParams(t.info)
	if e != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_INSTALL_FLAGS_UNREADABLE")
	}
	if p.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0 {
		out.FlagsReadable = true
		out.RestartRequired = true
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVAL_RESTART_REQUIRED")
	}
	if durableIntent == nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVAL_INTENT_REQUIRED")
	}
	// Quiet installation parameters affect this exact node only.
	p.Flags |= windows.DI_QUIETINSTALL
	if t.set.SetDeviceInstallParams(t.info, p) != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVE_PARAMETERS_FAILED")
	}
	remove := windows.RemoveDeviceParams{ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE), Scope: windows.DI_REMOVEDEVICE_GLOBAL}
	if t.set.SetClassInstallParams(t.info, &remove.ClassInstallHeader, uint32(unsafe.Sizeof(remove))) != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVE_PARAMETERS_FAILED")
	}
	// Independently re-enumerate the complete same binding immediately before
	// persisting intent, including normal/phantom/config proof in that route.
	fresh, _, err := open(index)
	if err != nil {
		return out, err
	}
	err = validateNativeHostRemovalTargets(t, fresh, nonpresent)
	fresh.set.Close()
	if err != nil {
		return out, err
	}

	if err = nativeHostIPv4Absent(t.network); err != nil {
		return out, err
	}
	if ctx.Err() != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVAL_CANCELLED")
	}
	if err = durableIntent(t.node.Instance); err != nil {
		return out, err
	}
	// Durable I/O may take time. Re-enumerate the full unique native binding
	// again rather than allowing the earlier observation to become authority.
	latest, _, err := open(index)
	if err != nil {
		return out, err
	}
	err = validateNativeHostRemovalTargets(t, latest, nonpresent)
	latest.set.Close()
	if err != nil {
		return out, err
	}
	if nonpresent {
		// The class-install request belongs to t's handle, not the newer set.
		// Re-read that exact retained handle after durable I/O and compare it
		// with the independent unique enumeration before invoking DIF_REMOVE.
		n, err := readNativeHostNode(t.set, t.info, t.node.SetupNetGUID)
		if err == nil || err.Error() != "USB_HOST_NATIVE_NODE_STATE_UNPROVEN" || n != t.node {
			return out, fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_TARGET_CHANGED")
		}
		proof, err := readNativeHostNonpresentProof(t)
		if err != nil {
			return out, err
		}
		if err = validateNativeHostNonpresentTransition(t.network, t.network, t.node, n, *t.nonpresent, proof); err != nil {
			return out, err
		}
	}
	if err = nativeHostIPv4Absent(t.network); err != nil {
		return out, err
	}
	p, err = t.set.DeviceInstallParams(t.info)
	if err != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_INSTALL_FLAGS_UNREADABLE")
	}
	if p.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0 {
		out.FlagsReadable = true
		out.RestartRequired = true
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVAL_RESTART_REQUIRED")
	}
	if ctx.Err() != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVAL_CANCELLED")
	}
	out.Attempted = true
	e = t.set.CallClassInstaller(windows.DIF_REMOVE, t.info)
	p, err = t.set.DeviceInstallParams(t.info)
	if err != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVE_FLAGS_UNREADABLE")
	}
	out.FlagsReadable = true
	out.RestartRequired = p.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0
	if out.RestartRequired {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVAL_RESTART_REQUIRED")
	}
	if e != nil {
		return out, fmt.Errorf("USB_HOST_NATIVE_REMOVE_FAILED")
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		absent, err := nativeHostRemovalAbsent(t.node.Instance)
		if err != nil {
			return out, err
		}
		if absent {
			out.AbsenceVerified = true
			return out, nil
		}
		select {
		case <-ctx.Done():
			return out, fmt.Errorf("USB_HOST_NATIVE_REMOVAL_CANCELLED")
		case <-deadline.C:
			return out, fmt.Errorf("USB_HOST_ADAPTER_ABSENCE_UNCONFIRMED")
		case <-ticker.C:
		}
	}
}

// The private instance comes only from the protected deletion intent. This is
// observation, never deletion authorization, and has no RPC entry point.
func ConfirmSharedHostRemovalAbsentNative(instance string) (bool, error) {
	if instance == "" || len(instance) > 1024 || strings.ContainsAny(instance, "*?\x00") {
		return false, fmt.Errorf("USB_HOST_NATIVE_ABSENCE_INSTANCE_INVALID")
	}
	return nativeHostRemovalAbsent(instance)
}

// ConfirmSharedHostAbsentNative checks the fixed interface and native PnP mapping.
func ConfirmSharedHostAbsentNative() (bool, error) { return nativeHostRemovalAbsent("") }
