//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"time"
	"unsafe"
)

var portableCfg = windows.NewLazySystemDLL("cfgmgr32.dll")
var portableParent = portableCfg.NewProc("CM_Get_Parent")
var portableID = portableCfg.NewProc("CM_Get_Device_IDW")

func descendantOfPortableRoot(dev windows.DEVINST, root string) (bool, error) {
	seen := map[uint32]bool{}
	for i := 0; i < 32; i++ {
		var parent uint32
		cr, _, _ := portableParent.Call(uintptr(unsafe.Pointer(&parent)), uintptr(dev), 0)
		if cr == 0x0d {
			return false, nil
		}
		if cr != 0 || seen[parent] {
			return false, fmt.Errorf("portable parent chain unavailable")
		}
		seen[parent] = true
		var b [1024]uint16
		cr, _, _ = portableID.Call(uintptr(parent), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
		if cr != 0 {
			return false, fmt.Errorf("portable parent identity unavailable")
		}
		id := windows.UTF16ToString(b[:])
		if strings.EqualFold(id, root) {
			return true, nil
		}
		dev = windows.DEVINST(parent)
	}
	return false, fmt.Errorf("portable parent chain limit")
}

func portableNodes(root string) ([]portableNodeReceipt, error) {
	if !validPortableReceipt(portableNodeReceipt{Root: root, ID: "scope-validation", Class: portableWPDClass}) {
		return nil, fmt.Errorf("unsupported portable root")
	}
	set, e := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if e != nil {
		return nil, e
	}
	defer set.Close()
	var nodes []portableNodeReceipt
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			return nodes, nil
		}
		if e != nil {
			return nil, e
		}
		if !portableClass(info.ClassGUID.String()) {
			continue
		}
		belongs, e := descendantOfPortableRoot(info.DevInst, root)
		if e != nil {
			return nil, e
		}
		if !belongs {
			continue
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			return nil, e
		}
		var status, problem uint32
		if e := windows.CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0); e != nil {
			return nil, e
		}
		flags, e := portableConfigFlags(set, info)
		if e != nil {
			return nil, e
		}
		n := portableNodeReceipt{Root: root, ID: id, Class: info.ClassGUID.String(), OriginalDisabled: problem == 22 || flags&1 != 0, ConfigFlags: flags}
		if !validPortableReceipt(n) {
			return nil, fmt.Errorf("portable target invalid")
		}
		nodes = append(nodes, n)
	}
	return nil, fmt.Errorf("portable enumeration limit")
}

// Read native properties from the actual CM instance; never infer a disabled
// state from an API success code or a stale SetupDi device-information record.
func portableNativeObservation(dev windows.DEVINST, n portableNodeReceipt) (s PortableNodeObservation) {
	var id [1024]uint16
	cr, _, _ := portableID.Call(uintptr(dev), uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)), 0)
	s.InstanceCR = uint32(cr)
	s.InstanceMatches = cr == 0 && strings.EqualFold(windows.UTF16ToString(id[:]), n.ID)
	if !s.InstanceMatches {
		s.Error = "CM_INSTANCE_CHANGED_OR_UNREADABLE"
		return
	}
	var typ windows.DEVPROPTYPE
	size := uint32(16)
	class := windows.GUID{}
	propertyGUID, _ := windows.GUIDFromString("{a45c254e-df1c-4efd-8020-67d146a850e0}")
	key := windows.DEVPROPKEY{FmtID: windows.DEVPROPGUID(propertyGUID), PID: 10}
	property := portableCfg.NewProc("CM_Get_DevNode_PropertyW")
	cr, _, _ = property.Call(uintptr(dev), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&class)), uintptr(unsafe.Pointer(&size)), 0)
	s.ClassCR = uint32(cr)
	s.ClassMatches = cr == 0 && typ == windows.DEVPROP_TYPE_GUID && size == 16 && strings.EqualFold(class.String(), n.Class)
	if !s.ClassMatches {
		s.Error = "CM_CLASS_CHANGED_OR_UNREADABLE"
		return
	}
	belongs, err := descendantOfPortableRoot(dev, n.Root)
	s.RootMatches = belongs && err == nil
	if !s.RootMatches {
		s.Error = "CM_PARENT_ROOT_CHANGED_OR_UNREADABLE"
		return
	}
	cr, _, _ = portableCfg.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&s.Status)), uintptr(unsafe.Pointer(&s.Problem)), uintptr(dev), 0)
	s.StateCR, s.StateReadable = uint32(cr), cr == 0
	if !s.StateReadable {
		s.Error = "CM_STATE_UNREADABLE"
		return
	}
	typ, size, key.PID = 0, 4, 12 // DEVPKEY_Device_ConfigFlags
	cr, _, _ = property.Call(uintptr(dev), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&s.ConfigFlags)), uintptr(unsafe.Pointer(&size)), 0)
	s.FlagsCR, s.FlagsType, s.FlagsSize = uint32(cr), uint32(typ), size
	s.FlagsAbsent = cr == 0x25 // CR_NO_SUCH_VALUE: same absent=zero rule as the original SetupDi read.
	s.FlagsReadable = cr == 0 && typ == windows.DEVPROP_TYPE_UINT32 && size == 4 || s.FlagsAbsent
	if s.FlagsAbsent {
		s.ConfigFlags = 0
	}
	if !s.FlagsReadable {
		s.Error = "CM_CONFIG_FLAGS_UNREADABLE_OR_WRONG_TYPE"
	}
	return
}

func restoreOwnedPortableNode(dir string, n portableNodeReceipt) (err error) {
	d, start := beginPortableOperation(n, false)
	defer func() {
		d.ElapsedMS = time.Since(start).Milliseconds()
		if err != nil {
			d.Outcome = err.Error()
		} else {
			if d.PhantomPropertyRestore {
				d.Outcome = "EXACT_OWNED_PHANTOM_RECORDED_VALUE_VERIFIED"
			} else {
				d.Outcome = "EXACT_NATIVE_STATE_AND_PROPERTY_VERIFIED"
			}
			if d.OriginalPresenceUnknown {
				d.Outcome += "_ORIGINAL_PRESENCE_UNKNOWN"
			}
		}
		networkOnlyOperationHistory.record(d)
	}()
	if !validPortableReceipt(n) {
		return fmt.Errorf("portable restore target invalid")
	}
	if e := verifyOwnedPortableReceipt(dir, n); e != nil {
		return e
	}
	original, e := portableOriginalMetadata(dir, n)
	if e != nil {
		return e
	}
	set, info, e := exactPortableTarget(n)
	if e != nil {
		return e
	}
	defer set.Close()
	{
		d.Before = portableNativeObservation(info.DevInst, n)
		if d.Before.InstanceMatches && d.Before.ClassMatches && d.Before.RootMatches && d.Before.StateCR == 13 {
			return restorePortablePhantom(dir, n, original, &d)
		}
		if e := d.Before.proofError(n.ConfigFlags); e != nil {
			return e
		}
		if d.Before.targetReadBack(n.ConfigFlags, false) {
			d.After = d.Before
			return finishPortablePresentRestore(dir, n, original, &d)
		}

		proc, flags := portableCfg.NewProc("CM_Enable_DevNode"), uint32(0)
		d.ChangeAttempted, d.ChangeFlags = true, flags
		cr, _, _ := proc.Call(uintptr(info.DevInst), uintptr(flags))
		d.ChangeCR = uint32(cr)
		if cr != 0 {
			return fmt.Errorf("portable node change CR_%d", cr)
		}
		// Re-resolve the exact instance after its state changes. A new DEVINST is
		// acceptable only if ID, class and full CM ancestor identity still match.
		target, e := windows.UTF16PtrFromString(n.ID)
		if e != nil {
			return e
		}
		var current windows.DEVINST
		cr, _, _ = portableCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&current)), uintptr(unsafe.Pointer(target)), 0)
		d.RelocateCR = uint32(cr)
		if cr != 0 {
			return fmt.Errorf("portable exact instance readback CR_%d; restoration retained", cr)
		}
		d.DevInstChanged = current != info.DevInst
		d.After = portableNativeObservation(current, n)
		if e := d.After.proofError(n.ConfigFlags); e != nil {
			return e
		}
		if !d.After.targetReadBack(n.ConfigFlags, false) {
			return fmt.Errorf("portable node change not read back: problem=%d status=0x%08x config_flags=0x%08x expected=0x%08x", d.After.Problem, d.After.Status, d.After.ConfigFlags, n.ConfigFlags)
		}
		return finishPortablePresentRestore(dir, n, original, &d)
	}
}

func portableConfigFlags(set windows.DevInfo, info *windows.DevInfoData) (uint32, error) {
	v, e := set.DeviceRegistryProperty(info, windows.SPDRP_CONFIGFLAGS)
	if e == windows.ERROR_INVALID_DATA || e == windows.ERROR_FILE_NOT_FOUND {
		return 0, nil
	}
	if e != nil {
		return 0, e
	}
	flags, ok := v.(uint32)
	if !ok {
		return 0, fmt.Errorf("portable config flags type invalid")
	}
	return flags, nil
}
