//go:build windows && amd64

package ipadncm

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"unsafe"
)

func ipadNativeString(dev windows.DEVINST, pid uint32) (string, error) {
	var b [512]uint16
	size := uint32(len(b) * 2)
	var typ windows.DEVPROPTYPE
	if softwareProperty(dev, pid, &typ, unsafe.Pointer(&b[0]), &size) != 0 || typ != windows.DEVPROP_TYPE_STRING || size < 2 || size%2 != 0 || size > uint32(len(b)*2) || b[size/2-1] != 0 {
		return "", errors.New("IPAD_PERSISTENT_NATIVE_PROPERTY_UNPROVEN")
	}
	for _, c := range b[:size/2-1] {
		if c == 0 {
			return "", errors.New("IPAD_PERSISTENT_NATIVE_PROPERTY_UNPROVEN")
		}
	}
	return windows.UTF16ToString(b[:size/2]), nil
}

// The protected binding is an obligation only. Each call independently proves
// the exact current root and child via CM/SetupDi, then their adapter mapping.
// No USB descriptor, pairing, arbitrary device or registry mutation occurs.
func verifyIPadPersistentNative(ctx context.Context, v interfaceconfig.IPadPersistentBinding) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("IPAD_PERSISTENT_CONTEXT_UNAVAILABLE")
	}
	set, e := windows.SetupDiGetClassDevsEx(nil, "USB", 0, windows.DIGCF_PRESENT|windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		return errors.New("IPAD_PERSISTENT_NATIVE_ENUM_UNREADABLE")
	}
	defer set.Close()
	rootCount, childCount := 0, 0
	var child Node
	complete := false
	for i := 0; i < 4096; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			complete = true
			break
		}
		if e != nil {
			return errors.New("IPAD_PERSISTENT_NATIVE_ENUM_UNREADABLE")
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			return errors.New("IPAD_PERSISTENT_NATIVE_ID_UNREADABLE")
		}
		isRoot, isChild := strings.EqualFold(id, v.Root), strings.EqualFold(id, v.Instance)
		if !isRoot && !isChild {
			continue
		}
		var located windows.DEVINST
		p, _ := windows.UTF16PtrFromString(id)
		cr, _, _ := portableCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&located)), uintptr(unsafe.Pointer(p)), 0)
		var status, problem uint32
		if cr != 0 || located != info.DevInst || windows.CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0) != nil || problem != 0 || status&8 == 0 || status&0x100 != 0 {
			return errors.New("IPAD_PERSISTENT_NATIVE_NODE_UNHEALTHY")
		}
		var configFlags uint32
		flagSize := uint32(4)
		var flagType windows.DEVPROPTYPE
		flagCR := softwareProperty(info.DevInst, 12, &flagType, unsafe.Pointer(&configFlags), &flagSize)
		if flagCR != 0x25 && (flagCR != 0 || flagType != windows.DEVPROP_TYPE_UINT32 || flagSize != 4 || configFlags != 0) {
			return errors.New("IPAD_PERSISTENT_NATIVE_FLAGS_UNPROVEN")
		}
		service, e := ipadNativeString(info.DevInst, 6)
		if e != nil {
			return e
		}
		registryService, e := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE)
		if e != nil || !strings.EqualFold(service, fmtString(registryService)) {
			return errors.New("IPAD_PERSISTENT_NATIVE_SERVICE_CHANGED")
		}
		driver, e := ipadNativeString(info.DevInst, 11) // DEVPKEY_Device_Driver; 9 is Device_Class
		if e != nil {
			return e
		}
		registryDriver, e := set.DeviceRegistryProperty(info, windows.SPDRP_DRIVER)
		if e != nil || !strings.EqualFold(driver, fmtString(registryDriver)) {
			return errors.New("IPAD_PERSISTENT_NATIVE_DRIVER_CHANGED")
		}
		var class windows.GUID
		size := uint32(16)
		var typ windows.DEVPROPTYPE
		if softwareProperty(info.DevInst, 10, &typ, unsafe.Pointer(&class), &size) != 0 || typ != windows.DEVPROP_TYPE_GUID || size != 16 || class != info.ClassGUID {
			return errors.New("IPAD_PERSISTENT_NATIVE_CLASS_UNPROVEN")
		}
		if isRoot {
			rootCount++
			if !strings.EqualFold(service, "usbccgp") || !strings.EqualFold(driver, v.Driver) {
				return errors.New("IPAD_PERSISTENT_ROOT_DRIVER_CHANGED")
			}
		}
		if isChild {
			childCount++
			if !strings.EqualFold(service, "UsbNcm") || !strings.EqualFold(class.String(), "{4D36E972-E325-11CE-BFC1-08002BE10318}") || !netDriverKeyPattern.MatchString(driver) {
				return errors.New("IPAD_PERSISTENT_NCM_CLASS_CHANGED")
			}
			belongs, e := descendantOfPortableRoot(info.DevInst, v.Root)
			if e != nil || !belongs {
				return errors.New("IPAD_PERSISTENT_NATIVE_ROOT_CHANGED")
			}
			child = Node{instanceID: id, devInst: info.DevInst, Service: "UsbNcm", DevNodeStatus: "0x00000008"}
		}
	}
	if !complete || rootCount != 1 || childCount != 1 {
		return errors.New("IPAD_PERSISTENT_EXACT_INSTANCES_UNPROVEN")
	}
	adapters := readNCMAdapters(Snapshot{Nodes: []Node{child}})
	if len(adapters) != 1 || !adapters[0].Matched || adapters[0].Error != "" || adapters[0].instanceID != v.Instance || adapters[0].InterfaceIndex != v.Scope.Index || adapters[0].luid != v.Scope.LUID || !strings.EqualFold(strings.SplitN(adapters[0].key, "/", 2)[0], v.Scope.GUID) {
		return errors.New("IPAD_PERSISTENT_NATIVE_MAPPING_CHANGED")
	}
	return ctx.Err()
}
func fmtString(v any) string { s, _ := v.(string); return s }
