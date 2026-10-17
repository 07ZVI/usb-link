//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

func (b *photoPolicyNativeStore) supported() error {
	v := windows.RtlGetVersion()
	var sku uint32
	ok, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProductInfo").Call(uintptr(v.MajorVersion), uintptr(v.MinorVersion), uintptr(v.ServicePackMajor), uintptr(v.ServicePackMinor), uintptr(unsafe.Pointer(&sku)))
	if ok == 0 || !photoPolicySupported(v.MajorVersion, v.BuildNumber, sku, v.ProductType == 1) {
		return errors.New("PHOTO_POLICY_WINDOWS_EDITION_OR_BUILD_UNSUPPORTED")
	}
	return nil
}
func photoPolicyParent(set windows.DevInfo, info *windows.DevInfoData) (string, error) {
	g, _ := windows.GUIDFromString("{4340a6c5-93fa-4706-972c-7b648008a5a7}")
	key := windows.DEVPROPKEY{FmtID: windows.DEVPROPGUID(g), PID: 8}
	var buf [1024]uint16
	var typ windows.DEVPROPTYPE
	var size uint32
	ok, _, _ := windows.NewLazySystemDLL("setupapi.dll").NewProc("SetupDiGetDevicePropertyW").Call(uintptr(set), uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&size)), 0)
	if ok == 0 || typ != windows.DEVPROP_TYPE_STRING || size < 2 || size > uint32(len(buf)*2) || size%2 != 0 {
		return "", errors.New("PHOTO_POLICY_PARENT_UNPROVEN")
	}
	return windows.UTF16ToString(buf[:size/2]), nil
}
func (b *photoPolicyNativeStore) scan(root string) (photoPolicyScan, error) {
	out := photoPolicyScan{}
	set, e := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		return out, photoWindowsFailure("PHOTO_POLICY_SCAN_FAILED", e)
	}
	defer set.Close()
	seen := map[string]bool{}
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			return out, nil
		}
		if e != nil {
			return out, photoWindowsFailure("PHOTO_POLICY_SCAN_FAILED", e)
		}
		if !portableClass(info.ClassGUID.String()) {
			continue
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			return out, errors.New("PHOTO_POLICY_ID_UNREADABLE")
		}
		if !localPhotoInstance.MatchString(id) {
			continue
		}
		// Windows 8+ preserves the parent property for historical instances.
		// An unproven parent is skipped, never reconstructed from the USB suffix.
		parent, e := photoPolicyParent(set, info)
		if e != nil || !strings.EqualFold(parent, root) {
			continue
		}
		compatible, e := set.DeviceRegistryProperty(info, windows.SPDRP_COMPATIBLEIDS)
		if e != nil {
			return out, errors.New("PHOTO_POLICY_PHOTO_CLASS_UNPROVEN")
		}
		ids, ok := compatible.([]string)
		photo := false
		if ok {
			for _, v := range ids {
				if strings.EqualFold(v, `USB\Class_06&SubClass_01&Prot_01`) {
					photo = true
				}
			}
		}
		if !photo {
			return out, errors.New("PHOTO_POLICY_PHOTO_CLASS_UNPROVEN")
		}
		flags, e := portableConfigFlags(set, info)
		if e != nil {
			return out, errors.New("PHOTO_POLICY_CONFIG_UNREADABLE")
		}
		var status, problem uint32
		cr, _, _ := portableCfg.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&problem)), uintptr(info.DevInst), 0)
		if cr != 0 && cr != 13 {
			return out, errors.New("PHOTO_POLICY_NATIVE_STATE_UNREADABLE")
		}
		if cr == 0 {
			out.Present++
			if status&0x40000 != 0 || problem == 14 {
				out.RestartRequired = true
			}
			if problem != 0 || status&8 == 0 || flags&1 != 0 {
				out.Unhealthy++
			}
		} else if flags&1 != 0 {
			out.Unhealthy++
		}
		n := portableNodeReceipt{Root: root, ID: id, Class: info.ClassGUID.String(), OriginalDisabled: problem == 22 || flags&1 != 0, ConfigFlags: flags}
		if !localPhotoReceiptValid(n) || seen[strings.ToUpper(id)] {
			return out, errors.New("PHOTO_POLICY_TARGET_AMBIGUOUS")
		}
		seen[strings.ToUpper(id)] = true
		if len(out.Nodes) >= localPhotoPolicyMaxNodes {
			return out, errors.New("PHOTO_POLICY_NODE_LIMIT")
		}
		out.Nodes = append(out.Nodes, n)
	}
	return out, errors.New("PHOTO_POLICY_ENUMERATION_LIMIT")
}
