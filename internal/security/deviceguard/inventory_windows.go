//go:build windows && amd64

// Package deviceguard observes PnP state without opening USB interfaces or
// reading input events. It never disables keyboard/mouse devices.
package deviceguard

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"unsafe"
)

var cfg = windows.NewLazySystemDLL("cfgmgr32.dll")
var getParent = cfg.NewProc("CM_Get_Parent")
var getID = cfg.NewProc("CM_Get_Device_IDW")
var getProperty = windows.NewLazySystemDLL("setupapi.dll").NewProc("SetupDiGetDevicePropertyW")
var containerKey = windows.DEVPROPKEY{FmtID: windows.DEVPROPGUID{Data1: 0x8c7ed206, Data2: 0x3f8a, Data3: 0x4827, Data4: [8]byte{0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c}}, PID: 2}

// Inventory includes non-USB input devices so a future host installation gate
// can preserve built-in keyboards and touchpads. Every failure is explicit;
// partial results must never establish a trusted baseline.
func Inventory(ctx context.Context) ([]securitypolicy.DeviceNode, error) {
	set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_PRESENT|windows.DIGCF_ALLCLASSES, 0, "")
	if err != nil {
		return nil, fmt.Errorf("PNP_INVENTORY_UNAVAILABLE")
	}
	defer set.Close()
	var nodes []securitypolicy.DeviceNode
	for i := 0; i < 4096; i++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		info, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			return nodes, nil
		}
		if err != nil {
			return nil, fmt.Errorf("PNP_ENUMERATION_FAILED")
		}
		id, err := set.DeviceInstanceID(info)
		if err != nil {
			return nil, fmt.Errorf("PNP_ID_UNAVAILABLE")
		}
		n := securitypolicy.DeviceNode{ID: id, ClassGUID: info.ClassGUID.String()}
		var container windows.GUID
		var propertyType, propertySize uint32
		result, _, _ := getProperty.Call(uintptr(set), uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&containerKey)), uintptr(unsafe.Pointer(&propertyType)), uintptr(unsafe.Pointer(&container)), 16, uintptr(unsafe.Pointer(&propertySize)), 0)
		if result != 0 && propertyType == 13 && propertySize == 16 && container != (windows.GUID{}) {
			n.ContainerID = container.String()
		}
		// Optional topology metadata is display-only. A missing property does not
		// turn the otherwise complete security inventory into a partial baseline.
		if paths, e := set.DeviceRegistryProperty(info, windows.SPDRP_LOCATION_PATHS); e == nil {
			n.LocationPaths, _ = paths.([]string)
		}
		if driver, e := set.DeviceRegistryProperty(info, windows.SPDRP_DRIVER); e == nil {
			n.DriverKey, _ = driver.(string)
		}
		name, nameErr := set.DeviceRegistryProperty(info, windows.SPDRP_FRIENDLYNAME)
		if nameErr != nil {
			name, _ = set.DeviceRegistryProperty(info, windows.SPDRP_DEVICEDESC)
		}
		n.Name, _ = name.(string)
		var parent uint32
		cr, _, _ := getParent.Call(uintptr(unsafe.Pointer(&parent)), uintptr(info.DevInst), 0)
		if cr == 0 {
			var b [200]uint16
			cr, _, _ = getID.Call(uintptr(parent), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
			if cr != 0 {
				return nil, fmt.Errorf("PNP_PARENT_ID_UNAVAILABLE")
			}
			n.Parent = windows.UTF16ToString(b[:])
		} else if cr != 0x0d || !strings.HasPrefix(strings.ToUpper(id), `HTREE\ROOT\`) {
			return nil, fmt.Errorf("PNP_PARENT_UNAVAILABLE")
		}
		service, err := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE)
		if err == nil {
			n.Service, _ = service.(string)
		} else if err != windows.ERROR_INVALID_DATA && err != windows.ERROR_FILE_NOT_FOUND {
			return nil, fmt.Errorf("PNP_SERVICE_UNAVAILABLE")
		}
		ids, err := set.DeviceRegistryProperty(info, windows.SPDRP_COMPATIBLEIDS)
		if err == nil {
			n.CompatibleIDs, _ = ids.([]string)
		} else if err != windows.ERROR_INVALID_DATA && err != windows.ERROR_FILE_NOT_FOUND {
			return nil, fmt.Errorf("PNP_CLASSES_UNAVAILABLE")
		}
		nodes = append(nodes, n)
	}
	return nil, fmt.Errorf("PNP_INVENTORY_LIMIT")
}

func CheckUSB(ctx context.Context, root string) securitypolicy.DeviceVerdict {
	nodes, err := Inventory(ctx)
	return securitypolicy.USBAdmission(root, nodes, err == nil)
}
