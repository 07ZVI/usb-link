//go:build windows && amd64

package netconfig

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"unsafe"
)

var hostCfg = windows.NewLazySystemDLL("cfgmgr32.dll")
var hostIP = windows.NewLazySystemDLL("iphlpapi.dll")
var hostSetup = windows.NewLazySystemDLL("setupapi.dll")

type nativeHostTarget struct {
	set        windows.DevInfo
	info       *windows.DevInfoData
	network    nativeHostInterface
	node       nativeHostNode
	nonpresent *nativeHostNonpresentProof
}

func readNativeHostInterface(index uint32) (nativeHostInterface, int, error) {
	return readNativeWintunInterface(index, usbaddress.HostGUID, usbaddress.HostName)
}
func readNativeWintunInterface(index uint32, expectedGUID, expectedAlias string) (nativeHostInterface, int, error) {
	var table *windows.MibIfTable2
	if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table) != nil || table == nil {
		return nativeHostInterface{}, 0, fmt.Errorf("USB_HOST_NATIVE_INTERFACE_QUERY_FAILED")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return nativeHostInterface{}, 0, fmt.Errorf("USB_HOST_NATIVE_INTERFACE_TABLE_INVALID")
	}
	var candidates []nativeHostInterface
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		guid, alias := r.InterfaceGuid.String(), windows.UTF16ToString(r.Alias[:])
		if strings.EqualFold(guid, expectedGUID) || alias == expectedAlias {
			candidates = append(candidates, nativeHostInterface{GUID: guid, Alias: alias, Type: r.Type, Index: r.InterfaceIndex, LUID: r.InterfaceLuid})
		}
	}
	f, e := validateNativeWintunInterface(candidates, index, expectedGUID, expectedAlias)
	if e != nil {
		return f, len(candidates), e
	}
	g, _ := windows.GUIDFromString(expectedGUID)
	var luid uint64
	rc, _, _ := hostIP.NewProc("ConvertInterfaceGuidToLuid").Call(uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&luid)))
	if rc != 0 || luid != f.LUID {
		return f, len(candidates), fmt.Errorf("USB_HOST_NATIVE_GUID_LUID_UNPROVEN")
	}
	r := windows.MibIfRow2{InterfaceLuid: luid}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r) != nil {
		return f, len(candidates), fmt.Errorf("USB_HOST_NATIVE_MAPPING_UNREADABLE")
	}
	got := nativeHostInterface{GUID: r.InterfaceGuid.String(), Alias: windows.UTF16ToString(r.Alias[:]), Type: r.Type, Index: r.InterfaceIndex, LUID: r.InterfaceLuid}
	if got != f {
		return f, len(candidates), fmt.Errorf("USB_HOST_NATIVE_MAPPING_CHANGED")
	}
	return f, len(candidates), nil
}

func nativeHostProperty(dev windows.DEVINST, pid uint32, buf unsafe.Pointer, size *uint32, typ *windows.DEVPROPTYPE) uint32 {
	g, _ := windows.GUIDFromString("{a45c254e-df1c-4efd-8020-67d146a850e0}")
	k := windows.DEVPROPKEY{FmtID: windows.DEVPROPGUID(g), PID: windows.DEVPROPID(pid)}
	rc, _, _ := hostCfg.NewProc("CM_Get_DevNode_PropertyW").Call(uintptr(dev), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(typ)), uintptr(buf), uintptr(unsafe.Pointer(size)), 0)
	return uint32(rc)
}

func nativeHostCMString(dev windows.DEVINST, pid uint32) (string, uint32, uint32, error) {
	var b [512]uint16
	var typ windows.DEVPROPTYPE
	size := uint32(len(b) * 2)
	if nativeHostProperty(dev, pid, unsafe.Pointer(&b[0]), &size, &typ) != 0 || typ != windows.DEVPROP_TYPE_STRING {
		return "", uint32(typ), size, fmt.Errorf("USB_HOST_NATIVE_PROPERTY_UNREADABLE")
	}
	s, ok := decodeNativeHostString(b[:], size)
	if !ok {
		return "", uint32(typ), size, fmt.Errorf("USB_HOST_NATIVE_PROPERTY_SHAPE_INVALID")
	}
	return s, uint32(typ), size, nil
}

func nativeHostRegistryGUID(key windows.Handle) (string, bool, error) {
	var b [64]uint16
	var typ uint32
	size := uint32(len(b) * 2)
	e := windows.RegQueryValueEx(key, windows.StringToUTF16Ptr("NetCfgInstanceId"), nil, &typ, (*byte)(unsafe.Pointer(&b[0])), &size)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return "", false, nil
	}
	if e != nil || typ != windows.REG_SZ {
		return "", false, fmt.Errorf("USB_HOST_NATIVE_BINDING_VALUE_UNREADABLE")
	}
	s, ok := decodeNativeHostString(b[:], size)
	if !ok || !hostGUIDText.MatchString(s) {
		return "", false, fmt.Errorf("USB_HOST_NATIVE_BINDING_VALUE_INVALID")
	}
	return s, true, nil
}

func nativeHostSetupDriver(set windows.DevInfo, info *windows.DevInfoData) (string, error) {
	var b [512]uint16
	var typ, size uint32
	rc, _, _ := hostSetup.NewProc("SetupDiGetDeviceRegistryPropertyW").Call(uintptr(set), uintptr(unsafe.Pointer(info)), uintptr(windows.SPDRP_DRIVER), uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)*2), uintptr(unsafe.Pointer(&size)))
	if rc == 0 || typ != windows.REG_SZ {
		return "", fmt.Errorf("USB_HOST_NATIVE_DRIVER_KEY_UNREADABLE")
	}
	s, ok := decodeNativeHostString(b[:], size)
	if !ok {
		return "", fmt.Errorf("USB_HOST_NATIVE_DRIVER_KEY_INVALID")
	}
	return s, nil
}

func readNativeHostNode(set windows.DevInfo, info *windows.DevInfoData, setupGUID string) (n nativeHostNode, e error) {
	return readNativeWintunNodeForGUID(set, info, setupGUID, usbaddress.HostGUID)
}
func readNativeWintunNodeForGUID(set windows.DevInfo, info *windows.DevInfoData, setupGUID, expectedGUID string) (n nativeHostNode, e error) {
	n, e = readNativeWintunNodeMetadata(set, info, setupGUID)
	if e != nil {
		return n, e
	}
	return n, validateNativeWintunNodeForGUID(n, expectedGUID)
}

// This private producer grants no ownership. Fixed callers separately validate
// their exact expected GUID and every typed field before trusting the result.
func readNativeWintunNodeMetadata(set windows.DevInfo, info *windows.DevInfoData, setupGUID string) (n nativeHostNode, e error) {
	n.SetupClass = info.ClassGUID.String()
	n.SetupNetGUID = setupGUID
	n.DevInst = uint32(info.DevInst)
	n.Instance, e = set.DeviceInstanceID(info)
	if e != nil {
		return n, fmt.Errorf("USB_HOST_NATIVE_INSTANCE_UNREADABLE")
	}
	var b [1024]uint16
	rc, _, _ := hostCfg.NewProc("CM_Get_Device_IDW").Call(uintptr(info.DevInst), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if rc != 0 {
		return n, fmt.Errorf("USB_HOST_NATIVE_INSTANCE_UNREADABLE")
	}
	n.CMInstance = windows.UTF16ToString(b[:])
	var typ windows.DEVPROPTYPE
	size := uint32(16)
	var class windows.GUID
	if nativeHostProperty(info.DevInst, 10, unsafe.Pointer(&class), &size, &typ) != 0 {
		return n, fmt.Errorf("USB_HOST_NATIVE_CLASS_UNREADABLE")
	}
	n.CMClass = class.String()
	n.ClassType = uint32(typ)
	n.ClassSize = size
	n.Service, n.ServiceType, n.ServiceSize, e = nativeHostCMString(info.DevInst, 6)
	if e != nil {
		return n, e
	}
	n.SetupDriver, e = nativeHostSetupDriver(set, info)
	if e != nil {
		return n, e
	}
	n.CMDriver, n.DriverType, n.DriverSize, e = nativeHostCMString(info.DevInst, 11)
	if e != nil {
		return n, e
	}
	// The CM handle is opened from the same devnode, not a registry path.
	// OpenExisting=1 and SOFTWARE=1; never create a key or request write access.
	var key windows.Handle
	rc, _, _ = hostCfg.NewProc("CM_Open_DevNode_Key").Call(uintptr(info.DevInst), windows.KEY_QUERY_VALUE, 0, 1, uintptr(unsafe.Pointer(&key)), 1)
	if rc != 0 {
		return n, fmt.Errorf("USB_HOST_NATIVE_CM_BINDING_UNREADABLE")
	}
	var found bool
	n.CMNetGUID, found, e = nativeHostRegistryGUID(key)
	windows.RegCloseKey(key)
	if e != nil || !found {
		return n, fmt.Errorf("USB_HOST_NATIVE_CM_BINDING_UNREADABLE")
	}
	var status, problem uint32
	stateErr := windows.CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0)
	n.StateReadable = stateErr == nil
	if code, ok := stateErr.(windows.CONFIGRET); ok {
		n.StateError = uint32(code)
	}
	n.Problem = problem
	return n, nil
}

func enumerateNativeHostNode(f nativeHostInterface) (*nativeHostTarget, int, error) {
	return enumerateNativeHostNodeMode(f, false)
}

func enumerateNativeHostNodeMode(f nativeHostInterface, nonpresent bool) (*nativeHostTarget, int, error) {
	class, _ := windows.GUIDFromString(hostNetClass)
	flags := windows.DIGCF_PRESENT
	if nonpresent {
		flags = 0
	}
	set, e := windows.SetupDiGetClassDevsEx(&class, "", 0, flags, 0, "")
	if e != nil {
		return nil, 0, fmt.Errorf("USB_HOST_NATIVE_PNP_ENUMERATION_FAILED")
	}
	success := false
	defer func() {
		if !success {
			set.Close()
		}
	}()
	var target *nativeHostTarget
	matches := 0
	complete := false
	for i := 0; i < 4096; i++ {
		info, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			complete = true
			break
		}
		if err != nil {
			return nil, matches, fmt.Errorf("USB_HOST_NATIVE_PNP_ENUMERATION_FAILED")
		}
		key, err := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err == windows.ERROR_FILE_NOT_FOUND {
			continue
		} // Confirmed absent software key has no GUID association.
		if err != nil {
			return nil, matches, fmt.Errorf("USB_HOST_NATIVE_SETUP_BINDING_UNREADABLE")
		}
		guid, present, err := nativeHostRegistryGUID(key)
		windows.RegCloseKey(key)
		if err != nil {
			return nil, matches, err
		}
		if !present || !strings.EqualFold(guid, f.GUID) {
			continue
		}
		matches++
		n, err := readNativeWintunNodeForGUID(set, info, guid, f.GUID)
		if err != nil && (!nonpresent || err.Error() != "USB_HOST_NATIVE_NODE_STATE_UNPROVEN") {
			return nil, matches, err
		}
		target = &nativeHostTarget{set: set, info: info, network: f, node: n}
		if nonpresent {
			p, err := readNativeHostNonpresentProof(target)
			if err != nil {
				return nil, matches, err
			}
			target.nonpresent = &p
			if err = validateNativeWintunNonpresent(n, p, f.GUID); err != nil {
				return nil, matches, err
			}
		}
	}
	if !complete || matches != 1 || target == nil {
		return nil, matches, fmt.Errorf("USB_HOST_NATIVE_PNP_BINDING_NOT_UNIQUE")
	}
	success = true
	return target, matches, nil
}

func openVerifiedNativeHost(index uint32) (*nativeHostTarget, HostIdentityDiagnostic, error) {
	return openVerifiedNativeHostMode(index, false)
}

func openVerifiedNativeHostMode(index uint32, nonpresent bool) (*nativeHostTarget, HostIdentityDiagnostic, error) {
	d := HostIdentityDiagnostic{NativeReadback: true, Phase: "native_interface"}
	f, count, e := readNativeHostInterface(index)
	d.AdapterCount = &count
	if e != nil {
		d.QueryError = e.Error()
		return nil, d, e
	}
	yes := true
	d.GUIDMatches = &yes
	d.AliasMatches = &yes
	d.IndexMatches = &yes
	d.Phase = "native_pnp_enumeration"
	first, matches, e := enumerateNativeHostRemovalNode(f, nonpresent)
	d.PnPCount = &matches
	if e != nil {
		d.QueryError = e.Error()
		return nil, d, e
	}
	defer first.set.Close()
	d.Phase = "native_recheck"
	fresh, _, e := readNativeHostInterface(index)
	if e != nil {
		d.QueryError = e.Error()
		return nil, d, e
	}
	final, matches, e := enumerateNativeHostRemovalNode(fresh, nonpresent)
	d.PnPCount = &matches
	if e != nil {
		d.QueryError = e.Error()
		return nil, d, e
	}
	e = validateNativeHostRemovalTargets(first, final, nonpresent)
	if e != nil {
		final.set.Close()
		d.QueryError = e.Error()
		return nil, d, e
	}
	d.Phase = "native_verified"
	d.InstanceNonempty = &yes
	d.InstanceWildcardFree = &yes
	d.ServiceWintun = &yes
	d.ClassNet = &yes
	d.ServiceType = final.node.ServiceType
	d.ServiceSize = final.node.ServiceSize
	d.ClassType = final.node.ClassType
	d.ClassSize = final.node.ClassSize
	return final, d, nil
}

// VerifySharedHostIdentityNative performs a new native observation every call.
// It exposes neither a target selector nor a cached diagnostic authorization.
func VerifySharedHostIdentityNative(index uint32) error {
	t, _, e := openVerifiedNativeHost(index)
	if t != nil {
		t.set.Close()
	}
	return e
}
