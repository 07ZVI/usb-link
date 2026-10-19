//go:build windows && amd64

package ipadncm

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const networkOnlyDriverUnproven = "NETWORK_ONLY_DRIVER_ADMISSION_UNPROVEN"

// NetworkOnlyDriverAdmission observes only. It cannot install a driver, start
// AMDS, write a choice/receipt, or grant USB consent. Ordinary non-I7 callers
// receive false/empty and retain their driver preparation flow. An active I7
// owner with incomplete proof must pause instead of starting its stopped AMDS.
func NetworkOnlyDriverAdmission(before Snapshot) (bool, string) {
	return networkOnlyDriverAdmission(before, false)
}

// Only the post-consent preparation caller can apply an initial policy. This
// proves a genuinely missing receipt and stable original service state, never
// supplies the expected-stop proof required by prepareDriver or post-mode work.
func NetworkOnlyPreparationAdmission(before Snapshot) (bool, string) {
	return networkOnlyDriverAdmission(before, true)
}

func networkOnlyDriverAdmission(before Snapshot, allowInitial bool) (bool, string) {
	networkOnly.Lock()
	available := networkOnly.available
	networkOnly.Unlock()
	if !available {
		return false, ""
	}
	// Admission needs a stage-5 candidate owner plus two observed mode-switch
	// proofs on this exact iPad. The candidate controller and the AMDS mode
	// diagnostic that established them no longer exist, so no owner scope can
	// match and every other check ends in the same unproven answer.
	return false, networkOnlyDriverUnproven
}

func networkOnlyDriverStoreProtected(dir string) bool {
	w, err := windows.GetWindowsDirectory()
	if err != nil || !strings.EqualFold(filepath.Clean(dir), filepath.Join(w, "Temp", "Suhang-iPad-Grouping-Recovery")) {
		return false
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || a&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return false
	}
	expected, err := windows.SecurityDescriptorFromString(groupingSDDL)
	if err != nil {
		return false
	}
	actual, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	return err == nil && groupingACLMatches(actual, expected)
}

func networkOnlyDriverRootHealthy(snapshot Snapshot, root string) (official, native bool) {
	var target *Node
	for i := range snapshot.Nodes {
		n := &snapshot.Nodes[i]
		if !strings.EqualFold(n.IDPrefix, `USB\VID_05AC&PID_12AB`) {
			continue
		}
		if target != nil || !strings.EqualFold(n.instanceID, root) {
			return false, false
		}
		target = n
	}
	if target == nil || target.devInst == 0 || target.Problem != 0 || target.StateError != "" || !strings.EqualFold(target.Service, "usbccgp") {
		return false, false
	}
	for _, filter := range target.LowerFilters {
		if strings.EqualFold(filter, "AppleLowerFilter") {
			official = true
		}
	}
	if !official {
		return false, false
	}
	var current windows.DEVINST
	id, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return official, false
	}
	cr, _, _ := portableCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&current)), uintptr(unsafe.Pointer(id)), 0)
	if cr != 0 || current != target.devInst {
		return official, false
	}
	var instance [1024]uint16
	cr, _, _ = portableID.Call(uintptr(target.devInst), uintptr(unsafe.Pointer(&instance[0])), uintptr(len(instance)), 0)
	if cr != 0 || !strings.EqualFold(windows.UTF16ToString(instance[:]), root) {
		return official, false
	}
	var status, problem uint32
	if windows.CM_Get_DevNode_Status(&status, &problem, target.devInst, 0) != nil || !networkOnlyDriverNativeHealthy(status, problem, 0, true) {
		return official, false
	}
	var typ windows.DEVPROPTYPE
	size, flags := uint32(4), uint32(0)
	propertyCR := softwareProperty(target.devInst, 12, &typ, unsafe.Pointer(&flags), &size)
	if propertyCR == 0x25 {
		return official, networkOnlyDriverNativeHealthy(status, problem, 0, true)
	}
	return official, networkOnlyDriverNativeHealthy(status, problem, flags, propertyCR == 0 && typ == windows.DEVPROP_TYPE_UINT32 && size == 4)
}
