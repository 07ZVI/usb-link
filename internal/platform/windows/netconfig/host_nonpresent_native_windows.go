//go:build windows && amd64

package netconfig

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readNativeHostNonpresentProof(t *nativeHostTarget) (p nativeHostNonpresentProof, e error) {
	if e = validateNativeWintunNodeIdentityForGUID(t.node, t.node.SetupNetGUID); e != nil {
		return p, e
	}
	id, e := windows.UTF16PtrFromString(t.node.Instance)
	if e != nil {
		return p, fmt.Errorf("USB_HOST_NATIVE_INSTANCE_UNPROVEN")
	}
	var normal, phantom windows.DEVINST
	rc, _, _ := hostCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&normal)), uintptr(unsafe.Pointer(id)), 0)
	p.NormalResult = uint32(rc)
	p.NormalReadable = true
	if p.NormalResult != uint32(windows.CR_NO_SUCH_DEVNODE) {
		return p, fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_NORMAL_UNPROVEN")
	}
	rc, _, _ = hostCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&phantom)), uintptr(unsafe.Pointer(id)), 1) // CM_LOCATE_DEVNODE_PHANTOM, observation only.
	p.PhantomReadable, p.PhantomResult = true, uint32(rc)
	if rc != 0 || phantom == 0 || phantom != t.info.DevInst {
		return p, fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_PHANTOM_UNPROVEN")
	}
	// Re-read all typed CM identity/driver properties using the independently
	// located exact phantom handle. No inferred registry path or missing field.
	n, e := readNativeWintunNodeForGUID(t.set, t.info, t.node.SetupNetGUID, t.node.SetupNetGUID)
	if e == nil || e.Error() != "USB_HOST_NATIVE_NODE_STATE_UNPROVEN" || n != t.node {
		return p, fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_PHANTOM_CHANGED")
	}
	if e = validateNativeWintunNodeIdentityForGUID(n, t.node.SetupNetGUID); e != nil {
		return p, e
	}
	p.PhantomExact = true
	var config, typ, size uint32
	rc, _, _ = hostSetup.NewProc("SetupDiGetDeviceRegistryPropertyW").Call(uintptr(t.set), uintptr(unsafe.Pointer(t.info)), uintptr(windows.SPDRP_CONFIGFLAGS), uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&config)), unsafe.Sizeof(config), uintptr(unsafe.Pointer(&size)))
	if rc == 0 {
		return p, fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_CONFIG_UNREADABLE")
	}
	p.ConfigReadable = true
	p.ConfigType, p.ConfigSize, p.Config = typ, size, config
	var cmConfig uint32
	var cmType windows.DEVPROPTYPE
	cmSize := uint32(4)
	cmResult := nativeHostProperty(phantom, 12, unsafe.Pointer(&cmConfig), &cmSize, &cmType) // DEVPKEY_Device_ConfigFlags
	p.CMConfigType, p.CMConfigSize, p.CMConfig = uint32(cmType), cmSize, cmConfig
	if cmResult != 0 {
		return p, fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_CM_CONFIG_UNREADABLE")
	}
	p.CMConfigReadable = true
	p.PresentMatches, p.InstalledMatches = 0, 1 // Complete set counts are checked by the caller.
	return p, nil
}

func enumerateNativeHostRemovalNode(f nativeHostInterface, nonpresent bool) (*nativeHostTarget, int, error) {
	if !nonpresent {
		return enumerateNativeHostNode(f)
	}
	// A phantom lookup alone includes present devices. Independently exclude
	// all present fixed-GUID candidates before considering an installed node.
	t, present, e := enumerateNativeHostNode(f)
	if t != nil {
		t.set.Close()
	}
	if present != 0 || e == nil || e.Error() != "USB_HOST_NATIVE_PNP_BINDING_NOT_UNIQUE" {
		return nil, present, fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_PRESENT_UNPROVEN")
	}
	return enumerateNativeHostNodeMode(f, true)
}

func validateNativeHostRemovalTargets(a, b *nativeHostTarget, nonpresent bool) error {
	if !nonpresent {
		return validateNativeHostTransition(a.network, b.network, a.node, b.node)
	}
	if a.nonpresent == nil || b.nonpresent == nil {
		return fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_UNPROVEN")
	}
	return validateNativeHostNonpresentTransition(a.network, b.network, a.node, b.node, *a.nonpresent, *b.nonpresent)
}

func openVerifiedNonpresentNativeHost(index uint32) (*nativeHostTarget, HostIdentityDiagnostic, error) {
	return openVerifiedNativeHostMode(index, true)
}

// Recovery may consider this additional lifecycle only after its original
// protected journal and unchanged LUID are checked by usbhost. This readback
// never provides permission to create an adapter or expose a healthy host.
func VerifySharedHostRecoveryIdentityNative(index uint32) (bool, error) {
	t, _, e := openVerifiedNativeHost(index)
	if t != nil {
		t.set.Close()
	}
	if e == nil || e.Error() != "USB_HOST_NATIVE_PNP_BINDING_NOT_UNIQUE" {
		return false, e
	}
	t, _, e = openVerifiedNonpresentNativeHost(index)
	if t != nil {
		t.set.Close()
	}
	return e == nil, e
}
