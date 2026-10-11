//go:build windows && amd64

package ipadncm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Enumerate the entire bounded ALL set. A prefix or the first matching record
// is insufficient ownership proof, even when a current MI_00 is also present.
func exactPortableTarget(n portableNodeReceipt) (windows.DevInfo, *windows.DevInfoData, error) {
	set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES, 0, "")
	if err != nil {
		return 0, nil, err
	}
	var found *windows.DevInfoData
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			if found != nil {
				return set, found, nil
			}
			set.Close()
			return 0, nil, fmt.Errorf("portable exact receipt target absent")
		}
		if e != nil {
			set.Close()
			return 0, nil, e
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			set.Close()
			return 0, nil, e
		}
		if !strings.EqualFold(id, n.ID) {
			continue
		}
		if found != nil || !strings.EqualFold(info.ClassGUID.String(), n.Class) {
			set.Close()
			return 0, nil, fmt.Errorf("portable exact target ambiguous or class changed")
		}
		found = info
	}
	set.Close()
	return 0, nil, fmt.Errorf("portable ALL enumeration limit")
}
func portablePresentCount(n portableNodeReceipt) (int, error) {
	set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return 0, err
	}
	defer set.Close()
	count := 0
	for i := 0; i < 4096; i++ {
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			return count, nil
		}
		if e != nil {
			return 0, e
		}
		id, e := set.DeviceInstanceID(info)
		if e != nil {
			return 0, e
		}
		if strings.EqualFold(id, n.ID) {
			count++
			if !strings.EqualFold(info.ClassGUID.String(), n.Class) {
				return 0, fmt.Errorf("portable PRESENT class changed")
			}
		}
	}
	return 0, fmt.Errorf("portable PRESENT enumeration limit")
}
func setupPortableProperty(set windows.DevInfo, info *windows.DevInfoData) portablePropertyReadback {
	v, e := set.DeviceRegistryProperty(info, windows.SPDRP_CONFIGFLAGS)
	if e == windows.ERROR_INVALID_DATA || e == windows.ERROR_FILE_NOT_FOUND {
		return portablePropertyReadback{Readable: true}
	}
	if e != nil {
		return portablePropertyReadback{}
	}
	flags, ok := v.(uint32)
	if !ok {
		return portablePropertyReadback{}
	}
	return portablePropertyReadback{Readable: true, Present: true, Type: 4, Size: 4, Value: flags}
}

// Independently ask CM for this exact instance's documented registry property.
// Device Parameters hardware keys are not a substitute for ConfigFlags.
func registryPortableProperty(set windows.DevInfo, info *windows.DevInfoData) portablePropertyReadback {
	var typ, value uint32
	size := uint32(4)
	cr, _, _ := portableCfg.NewProc("CM_Get_DevNode_Registry_PropertyW").Call(uintptr(info.DevInst), 0xB, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&size)), 0) // CM_DRP_CONFIGFLAGS
	if cr == 0x25 {
		return portablePropertyReadback{Readable: true}
	} // CR_NO_SUCH_VALUE
	if cr != 0 || typ != 4 || size != 4 {
		return portablePropertyReadback{}
	}
	return portablePropertyReadback{Readable: true, Present: true, Type: typ, Size: size, Value: value}
}
func readPortableProperties(n portableNodeReceipt) (portablePhantomProof, PortableNodeObservation, error) {
	var p portablePhantomProof
	var observation PortableNodeObservation
	set, info, err := exactPortableTarget(n)
	if err != nil {
		return p, observation, err
	}
	defer set.Close()
	observation = portableNativeObservation(info.DevInst, n)
	p.Unique, p.Instance, p.Class, p.Root = true, observation.InstanceMatches, observation.ClassMatches, observation.RootMatches
	p.StateCR = observation.StateCR
	count, err := portablePresentCount(n)
	if err != nil {
		return p, observation, err
	}
	p.PresenceReadable, p.Absent = true, count == 0
	if count > 1 {
		return p, observation, fmt.Errorf("portable PRESENT target ambiguous")
	}
	p.Setup, p.Registry = setupPortableProperty(set, info), registryPortableProperty(set, info)
	return p, observation, nil
}
func capturePortableOriginalBeforeDisable(dir string, n portableNodeReceipt) error {
	if n.OriginalDisabled {
		return nil
	}
	p, s, err := readPortableProperties(n)
	if err != nil {
		return err
	}
	if !p.Unique || !p.PresenceReadable || p.Absent {
		return fmt.Errorf("portable original target presence unproven")
	}
	original, err := portableOriginalBeforeDisable(n, s, p.Setup, p.Registry)
	if err != nil {
		return err
	}
	return savePortableOriginalMetadata(dir, original)
}
func setPortableConfigProperty(set windows.DevInfo, info *windows.DevInfoData, p *portablePropertyOriginal) error {
	if p == nil || !p.valid() {
		return fmt.Errorf("portable property target invalid")
	}
	if p.Present {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], p.Value)
		return windows.SetupDiSetDeviceRegistryProperty(set, info, windows.SPDRP_CONFIGFLAGS, b[:])
	}
	// x/sys v0.48's wrapper indexes buffer[0]. Clearing must pass NULL explicitly.
	proc := windows.NewLazySystemDLL("setupapi.dll").NewProc("SetupDiSetDeviceRegistryPropertyW")
	ok, _, err := proc.Call(uintptr(set), uintptr(unsafe.Pointer(info)), uintptr(windows.SPDRP_CONFIGFLAGS), 0, 0)
	if ok == 0 {
		return fmt.Errorf("portable property absence restore failed: %w", err)
	}
	return nil
}
func savePortableRestoreAudit(dir string, n portableNodeReceipt, original *portablePropertyOriginal, phantom bool, before, after portablePropertyReadback, verified bool) error {
	a := portableLegacyValueAudit{Node: n, OriginalPresenceUnknown: original == nil, Phantom: phantom, Before: before, After: after, ValueReadbackVerified: verified}
	if original != nil {
		a.OriginalPresencePresent = original.Present
		a.OriginalPresenceVerified = verified && after.original(*original)
	}
	return savePortableLegacyAudit(dir, a)
}
func restorePortablePhantom(dir string, n portableNodeReceipt, original *portablePropertyOriginal, d *PortableNodeOperationDiagnostic) error {
	d.PhantomPropertyRestore = true
	d.OriginalPresenceUnknown = original == nil
	read := func() (portablePhantomProof, error) { p, s, e := readPortableProperties(n); d.After = s; return p, e }
	write := func(target *portablePropertyOriginal) error {
		if err := verifyOwnedPortableReceipt(dir, n); err != nil {
			return err
		}
		p, _, err := readPortableProperties(n)
		if err != nil {
			return err
		}
		if err = p.owned(n.ConfigFlags); err != nil {
			return err
		}
		set, info, err := exactPortableTarget(n)
		if err != nil {
			return err
		}
		defer set.Close()
		// Recheck this same record immediately before touching its single property.
		s := portableNativeObservation(info.DevInst, n)
		if !s.InstanceMatches || !s.ClassMatches || !s.RootMatches || s.StateCR != 13 {
			return fmt.Errorf("portable phantom changed before property write")
		}
		setup, reg := setupPortableProperty(set, info), registryPortableProperty(set, info)
		if !setup.same(reg) || reg.Value != n.ConfigFlags && reg.Value != n.ConfigFlags|1 {
			return fmt.Errorf("portable phantom property changed before write")
		}
		d.ChangeAttempted = true
		return setPortableConfigProperty(set, info, target)
	}
	audit := func(before, after portablePhantomProof, verified bool) error {
		return savePortableRestoreAudit(dir, n, original, true, before.Registry, after.Registry, verified)
	}
	after, err := restoreOwnedPhantomProperty(n, original, read, write, audit)
	if err == nil {
		d.RecordedValueRestored = true
		d.OriginalPresenceVerified = original != nil && after.Registry.original(*original)
	}
	return err
}

// A present node still requires CM Enable and independently verified native
// state. This final step restores exact original presence only when recorded.
func finishPortablePresentRestore(dir string, n portableNodeReceipt, original *portablePropertyOriginal, d *PortableNodeOperationDiagnostic) error {
	before, s, err := readPortableProperties(n)
	if err != nil {
		return err
	}
	if before.Absent || !before.Setup.same(before.Registry) || !s.targetReadBack(n.ConfigFlags, false) || before.Registry.Value != n.ConfigFlags {
		return fmt.Errorf("portable present restoration proof changed")
	}
	if err = savePortableRestoreAudit(dir, n, original, false, before.Registry, portablePropertyReadback{}, false); err != nil {
		return err
	}
	if original != nil && !before.Registry.original(*original) {
		if err = verifyOwnedPortableReceipt(dir, n); err != nil {
			return err
		}
		set, info, e := exactPortableTarget(n)
		if e != nil {
			return e
		}
		fresh := portableNativeObservation(info.DevInst, n)
		setup, reg := setupPortableProperty(set, info), registryPortableProperty(set, info)
		if !fresh.targetReadBack(n.ConfigFlags, false) || !setup.same(reg) || reg.Value != n.ConfigFlags {
			set.Close()
			return fmt.Errorf("portable present property changed before write")
		}
		d.ChangeAttempted = true
		err = setPortableConfigProperty(set, info, original)
		set.Close()
		if err != nil {
			return err
		}
	}
	after, s, err := readPortableProperties(n)
	if err != nil {
		return err
	}
	d.After = s
	if after.Absent || !after.Setup.same(after.Registry) || !s.targetReadBack(n.ConfigFlags, false) || after.Registry.Value != n.ConfigFlags || original != nil && !after.Registry.original(*original) {
		return fmt.Errorf("portable present original property readback failed")
	}
	if err = savePortableRestoreAudit(dir, n, original, false, before.Registry, after.Registry, true); err != nil {
		return err
	}
	d.RecordedValueRestored = true
	d.OriginalPresenceUnknown = original == nil
	d.OriginalPresenceVerified = original != nil
	return nil
}
