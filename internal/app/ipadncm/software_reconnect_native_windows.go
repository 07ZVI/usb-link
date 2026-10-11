//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"suhang/usbnet/internal/security/deviceguard"
)

type softwareReconnectScope struct {
	snapshot  Snapshot
	root      string
	devInst   windows.DEVINST
	parent    string
	locations []string
}
type softwareReconnectNativeBackend struct {
	store   *softwareReconnectStore
	scope   softwareReconnectScope
	journal softwareReconnectJournal
}

func softwareProperty(dev windows.DEVINST, pid uint32, typ *windows.DEVPROPTYPE, buf unsafe.Pointer, size *uint32) uint32 {
	g, _ := windows.GUIDFromString("{a45c254e-df1c-4efd-8020-67d146a850e0}")
	key := windows.DEVPROPKEY{FmtID: windows.DEVPROPGUID(g), PID: windows.DEVPROPID(pid)}
	cr, _, _ := portableCfg.NewProc("CM_Get_DevNode_PropertyW").Call(uintptr(dev), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(typ)), uintptr(buf), uintptr(unsafe.Pointer(size)), 0)
	return uint32(cr)
}
func softwareParentID(dev windows.DEVINST) (string, uint32) {
	var parent uint32
	cr, _, _ := portableParent.Call(uintptr(unsafe.Pointer(&parent)), uintptr(dev), 0)
	if cr != 0 {
		return "", uint32(cr)
	}
	var id [1024]uint16
	cr, _, _ = portableID.Call(uintptr(parent), uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)), 0)
	if cr != 0 {
		return "", uint32(cr)
	}
	return windows.UTF16ToString(id[:]), 0
}

// Resolve the owning devnode of the enumerated hub interface through CfgMgr32.
// Interface path syntax is opaque: do not infer its instance ID by splitting it.
func softwareHubInstance(ctx context.Context, hub string) (string, uint32) {
	if ctx.Err() != nil {
		return "", ^uint32(0)
	}
	path, e := windows.UTF16PtrFromString(hub)
	if e != nil {
		return "", ^uint32(0)
	}
	guid, _ := windows.GUIDFromString("{78c34fc8-104a-4aca-9ea4-524d52996e57}")
	key := windows.DEVPROPKEY{FmtID: windows.DEVPROPGUID(guid), PID: 256}
	var typ windows.DEVPROPTYPE
	var id [1024]uint16
	size := uint32(len(id) * 2)
	cr, _, _ := portableCfg.NewProc("CM_Get_Device_Interface_PropertyW").Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&id[0])), uintptr(unsafe.Pointer(&size)), 0)
	if cr != 0 || typ != windows.DEVPROP_TYPE_STRING || size < 2 || size > uint32(len(id)*2) || size%2 != 0 {
		return "", uint32(cr)
	}
	return windows.UTF16ToString(id[:]), uint32(cr)
}

func softwareRootInfo(ctx context.Context, root string) (windows.DevInfo, *windows.DevInfoData, []string, error) {
	set, e := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if e != nil {
		return 0, nil, nil, e
	}
	roots := 0
	var target *windows.DevInfoData
	var locations []string
	for i := 0; i < 4096; i++ {
		if e := ctx.Err(); e != nil {
			set.Close()
			return 0, nil, nil, e
		}
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			if roots != 1 || target == nil {
				set.Close()
				return 0, nil, nil, fmt.Errorf("software reconnect exact native root not unique")
			}
			return set, target, locations, nil
		}
		if e != nil {
			set.Close()
			return 0, nil, nil, e
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			set.Close()
			return 0, nil, nil, e
		}
		parts := strings.Split(id, `\`)
		if len(parts) != 3 || !strings.EqualFold(parts[0]+`\`+parts[1], `USB\VID_05AC&PID_12AB`) {
			continue
		}
		roots++
		if !strings.EqualFold(id, root) {
			continue
		}
		target = info
		value, e := set.DeviceRegistryProperty(info, windows.SPDRP_LOCATION_PATHS)
		if e != nil {
			set.Close()
			return 0, nil, nil, fmt.Errorf("software reconnect physical location unreadable")
		}
		locations, _ = value.([]string)
	}
	set.Close()
	return 0, nil, nil, fmt.Errorf("software reconnect native root enumeration incomplete")
}
func softwareRootObserve(ctx context.Context, j softwareReconnectJournal) (o SoftwareReconnectNativeObservation, dev windows.DEVINST) {
	set, info, locations, e := softwareRootInfo(ctx, j.RootID)
	if e != nil {
		o.Error = e.Error()
		return
	}
	defer set.Close()
	o.UniqueRoot = true
	dev = info.DevInst
	var current windows.DEVINST
	p, _ := windows.UTF16PtrFromString(j.RootID)
	cr, _, _ := portableCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&current)), uintptr(unsafe.Pointer(p)), 0)
	o.LocateCR = uint32(cr)
	if cr != 0 || current != dev {
		o.Error = "software reconnect native root instance changed during lookup"
		return
	}
	var id [1024]uint16
	cr, _, _ = portableID.Call(uintptr(dev), uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)), 0)
	o.InstanceCR = uint32(cr)
	o.ExactInstance = cr == 0 && strings.EqualFold(windows.UTF16ToString(id[:]), j.RootID)
	var typ windows.DEVPROPTYPE
	size := uint32(16)
	var class windows.GUID
	o.ClassCR = softwareProperty(dev, 10, &typ, unsafe.Pointer(&class), &size)
	// Bounded class metadata only; not a device instance, serial or driver path.
	// The exact fixed-class admission predicate below remains unchanged.
	o.CMClassGUID, o.ClassPropertyType, o.ClassPropertySize = class.String(), uint32(typ), size
	o.SetupClassGUID, o.ExpectedClassGUID = info.ClassGUID.String(), softwareReconnectRootClass
	o.ExactClass = o.ClassCR == 0 && typ == windows.DEVPROP_TYPE_GUID && size == 16 && strings.EqualFold(class.String(), j.Class) && strings.EqualFold(info.ClassGUID.String(), j.Class)
	var service [256]uint16
	size = uint32(len(service) * 2)
	typ = 0
	o.ServiceCR = softwareProperty(dev, 6, &typ, unsafe.Pointer(&service[0]), &size)
	o.ExactService = o.ServiceCR == 0 && typ == windows.DEVPROP_TYPE_STRING && size >= 2 && size <= uint32(len(service)*2) && size%2 == 0 && strings.EqualFold(windows.UTF16ToString(service[:]), j.Service)
	parent, parentCR := softwareParentID(dev)
	o.ParentCR = parentCR
	hubInstance, hubCR := softwareHubInstance(ctx, j.Hub)
	o.HubInstanceCR = hubCR
	o.HubParentMatches = hubCR == 0 && hubInstance != "" && strings.EqualFold(hubInstance, parent)
	o.ExactParent = parentCR == 0 && strings.EqualFold(parent, j.ParentID)
	o.ExactLocation = reflect.DeepEqual(locations, j.LocationPaths)
	cr, _, _ = portableCfg.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&o.Status)), uintptr(unsafe.Pointer(&o.Problem)), uintptr(dev), 0)
	o.StateCR, o.StateReadable = uint32(cr), cr == 0
	typ, size = 0, 4
	o.FlagsCR = softwareProperty(dev, 12, &typ, unsafe.Pointer(&o.ConfigFlags), &size)
	o.FlagsPresent = o.FlagsCR == 0
	o.FlagsReadable = o.FlagsCR == 0 && typ == windows.DEVPROP_TYPE_UINT32 && size == 4 || o.FlagsCR == 0x25
	if o.FlagsCR == 0x25 {
		o.ConfigFlags = 0
	}
	// This is independent cached physical port evidence, not CM return-code or
	// device-change-notification evidence. It never sends descriptors or 0x52.
	physical := inventoryProduct(ctx, 0x12ab)
	o.ExactPhysicalPort = physical.Error == "" && physical.HubErrors == 0 && len(physical.Devices) == 1 && strings.EqualFold(physical.Devices[0].hub, j.Hub) && physical.Devices[0].port == j.Port && physical.Devices[0].CurrentConfiguration == j.Configuration
	if !o.ExactInstance || !o.ExactClass || !o.ExactService || !o.ExactParent || !o.HubParentMatches || !o.ExactLocation || !o.ExactPhysicalPort || !o.StateReadable || !o.FlagsReadable {
		o.Error = "software reconnect exact native/physical proof incomplete"
	}
	return
}
func captureSoftwareScope(ctx context.Context, expected string) (softwareReconnectScope, error) {
	s := inventory(ctx)
	if !networkOnlyUSBEligible(s) || !strings.EqualFold(exactIPadRoot(s), expected) {
		return softwareReconnectScope{}, fmt.Errorf("software reconnect requires same currently identified iPad")
	}
	if verdict := deviceguard.CheckUSB(ctx, expected); !verdict.Admit {
		return softwareReconnectScope{}, fmt.Errorf("software reconnect USB security admission failed: %s", verdict.Code)
	}
	set, info, locations, e := softwareRootInfo(ctx, expected)
	if e != nil {
		return softwareReconnectScope{}, e
	}
	defer set.Close()
	parent, cr := softwareParentID(info.DevInst)
	hubInstance, hubCR := softwareHubInstance(ctx, s.Devices[0].hub)
	if cr != 0 || parent == "" || len(locations) == 0 || hubCR != 0 || !strings.EqualFold(hubInstance, parent) {
		return softwareReconnectScope{}, fmt.Errorf("software reconnect parent/location proof unavailable")
	}
	return softwareReconnectScope{snapshot: s, root: expected, devInst: info.DevInst, parent: parent, locations: append([]string(nil), locations...)}, nil
}
func (b *softwareReconnectNativeBackend) CurrentIdentifiedTarget(ctx context.Context) (softwareReconnectTarget, error) {
	fresh, e := captureSoftwareScope(ctx, b.scope.root)
	if e != nil {
		return softwareReconnectTarget{}, e
	}
	if !sameSoftwareReconnectScope(b.scope, fresh) {
		return softwareReconnectTarget{}, fmt.Errorf("software reconnect request attachment replaced")
	}
	set, info, locations, e := softwareRootInfo(ctx, b.scope.root)
	if e != nil {
		return softwareReconnectTarget{}, e
	}
	defer set.Close()
	parent, cr := softwareParentID(info.DevInst)
	if cr != 0 {
		return softwareReconnectTarget{}, fmt.Errorf("software reconnect root parent unavailable")
	}
	d := fresh.snapshot.Devices[0]
	j := softwareReconnectJournal{Version: 1, StartedUTC: time.Now().UTC().Format(time.RFC3339Nano), RootID: b.scope.root, HardwarePrefix: `USB\VID_05AC&PID_12AB`, Class: softwareReconnectRootClass, Service: "usbccgp", Hub: d.hub, Port: d.port, ParentID: parent, LocationPaths: locations, Configuration: d.CurrentConfiguration, Product: d.USBProduct}
	o, _ := softwareRootObserve(ctx, j)
	recordSoftwareNative("preflight", o, 0)
	if !o.ExactInstance || !o.ExactClass || !o.ExactService || !o.ExactParent || !o.HubParentMatches || !o.ExactLocation || !o.ExactPhysicalPort || !o.UniqueRoot || !o.StateReadable || !o.FlagsReadable {
		return softwareReconnectTarget{}, fmt.Errorf("software reconnect preflight native proof incomplete")
	}
	j.Status, j.Problem, j.ConfigFlags, j.FlagsPresent = o.Status, o.Problem, o.ConfigFlags, o.FlagsPresent
	if !j.valid() {
		return softwareReconnectTarget{}, fmt.Errorf("software reconnect original enabled/disableable root unproven")
	}
	b.journal = j
	return softwareReconnectTarget{RootID: j.RootID, HardwarePrefix: j.HardwarePrefix, Class: j.Class, Service: j.Service, Status: j.Status, Problem: j.Problem, ConfigFlags: j.ConfigFlags, AuthorizedFixedAction: true, CurrentLauncherIdentity: true, ExactPhysicalRoot: true, StateAndPropertiesReadable: true, CleanupVerified: true}, nil
}
func (b *softwareReconnectNativeBackend) SaveProtectedReceipt(softwareReconnectReceipt) error {
	return b.store.Save(b.journal)
}
func (b *softwareReconnectNativeBackend) QuietDisableAndVerify(ctx context.Context, _ softwareReconnectReceipt, flags uint32) error {
	if flags != softwareReconnectQuietFlags || ctx.Err() != nil {
		return fmt.Errorf("software reconnect fixed flags/context invalid")
	}
	before, dev := softwareRootObserve(ctx, b.journal)
	recordSoftwareNative("before_disable", before, 0)
	if !before.enabled(b.journal) || before.Status&0x2000 == 0 || dev != b.scope.devInst {
		return fmt.Errorf("software reconnect target changed before disable")
	}
	cr, _, _ := portableCfg.NewProc("CM_Disable_DevNode").Call(uintptr(dev), uintptr(flags))
	recordSoftwareNative("disable_call", before, uint32(cr))
	if cr != 0 {
		return fmt.Errorf("software reconnect quiet disable CR_%d", cr)
	}
	after, _ := softwareRootObserve(ctx, b.journal)
	recordSoftwareNative("disabled_readback", after, uint32(cr))
	if !after.disabled(b.journal) {
		return fmt.Errorf("software reconnect temporary disabled state not independently proven")
	}
	return nil
}
func (b *softwareReconnectNativeBackend) Wait(ctx context.Context, d time.Duration) error {
	if d != softwareReconnectPause {
		return fmt.Errorf("software reconnect fixed pause invalid")
	}
	softwareReconnectPhase("temporary_pause_5s")
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (b *softwareReconnectNativeBackend) EnableAndVerifyOriginal(ctx context.Context, _ softwareReconnectReceipt) error {
	softwareReconnectPhase("restoring_original_root")
	before, dev := softwareRootObserve(ctx, b.journal)
	recordSoftwareNative("before_restore", before, 0)
	if !before.owned(b.journal) {
		return fmt.Errorf("software reconnect original root ownership unproven; receipt retained")
	}
	if before.enabled(b.journal) {
		return nil
	}
	if !before.disabled(b.journal) {
		return fmt.Errorf("software reconnect original root has external state change; receipt retained")
	}
	cr, _, _ := portableCfg.NewProc("CM_Enable_DevNode").Call(uintptr(dev), 0)
	recordSoftwareNative("enable_call", before, uint32(cr))
	if cr != 0 {
		return fmt.Errorf("software reconnect enable CR_%d; receipt retained", cr)
	}
	after, _ := softwareRootObserve(ctx, b.journal)
	recordSoftwareNative("enabled_readback", after, uint32(cr))
	if !after.enabled(b.journal) {
		return fmt.Errorf("software reconnect original enabled state not independently proven; receipt retained")
	}
	return nil
}
func (b *softwareReconnectNativeBackend) RemoveVerifiedReceipt(softwareReconnectReceipt) error {
	return b.store.Remove()
}

// A WM_DEVICECHANGE notification is not an attachment epoch: our own network
// cleanup also emits it. Compare fresh native and physical identity instead.
// This proves the current target, not an unobserved physical cable cycle.
func sameSoftwareReconnectScope(a, b softwareReconnectScope) bool {
	if len(a.snapshot.Devices) != 1 || len(b.snapshot.Devices) != 1 {
		return false
	}
	return softwareScopeAttachment(a).same(softwareScopeAttachment(b)) && sameRootInstance(a.snapshot, b.snapshot)
}

// Only the connection owner may call this after all preceding session cleanup
// was verified. A new native handle/configuration can be caused by legitimate
// grouping restoration; the exact allowed physical-root chain cannot change.
func refreshSoftwareScopeAfterVerifiedCleanup(ctx context.Context, prior softwareReconnectScope) (softwareReconnectScope, error) {
	fresh, err := captureSoftwareScope(ctx, prior.root)
	if err != nil {
		return softwareReconnectScope{}, err
	}
	if !softwareScopeAttachment(prior).samePhysicalRoot(softwareScopeAttachment(fresh)) || !sameRootInstance(prior.snapshot, fresh.snapshot) {
		return softwareReconnectScope{}, fmt.Errorf("software reconnect original authorized root/physical chain changed during cleanup")
	}
	return fresh, nil
}
func softwareScopeAttachment(s softwareReconnectScope) softwareReconnectAttachment {
	if len(s.snapshot.Devices) != 1 {
		return softwareReconnectAttachment{}
	}
	d := s.snapshot.Devices[0]
	return softwareReconnectAttachment{root: s.root, parent: s.parent, hub: d.hub, locations: s.locations, devInst: uint32(s.devInst), port: d.port, pid: d.pid}
}

func validSoftwareReconnectRequestScope(a, b softwareReconnectScope, priorCleanupVerified bool) bool {
	if priorCleanupVerified {
		return softwareScopeAttachment(a).samePhysicalRoot(softwareScopeAttachment(b)) && sameRootInstance(a.snapshot, b.snapshot)
	}
	return sameSoftwareReconnectScope(a, b)
}
