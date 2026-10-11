//go:build windows && amd64

package ipadncm

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
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
	if unpairedExperimentOwnsNetworkOnly() {
		return unpairedExperimentDriverAdmission(before)
	}
	networkOnly.Lock()
	dir, available, enabled := networkOnly.dir, networkOnly.available, networkOnly.enabled
	unresolved := networkOnly.busy || networkOnly.pending || networkOnly.blocked
	networkOnly.Unlock()
	if !available {
		return false, ""
	}
	if !enabled || unresolved || dir == "" {
		return false, networkOnlyDriverUnproven
	}
	ctx := connectionContext()
	if ctx == nil || ctx.Err() != nil || !networkOnlyUSBEligible(before) {
		return false, networkOnlyDriverUnproven
	}
	root := exactIPadRoot(before)
	p := networkOnlyDriverProof{descriptorBound: true}
	ipadCandidateControl.Lock()
	stage, scope := ipadCandidateControl.stage, ipadCandidateControl.scope
	ownerReady := !ipadCandidateControl.busy && !ipadCandidateControl.pending && !ipadCandidateControl.blocked
	ipadCandidateControl.Unlock()
	proofRoot, proved := observedIPadModeProofs.scope()
	p.ownerScope = networkOnlyDriverOwnerMatches(stage, scope, ownerReady, proofRoot, proved, root)
	p.storeProtected = networkOnlyDriverStoreProtected(dir)
	if !p.ownerScope || !p.storeProtected {
		return false, networkOnlyDriverUnproven
	}
	// Preserve InitNetworkOnly's missing-choice default ON, but only under the
	// current stage-5 owner plus same-root dual mode and protected receipt proof.
	b, err := readProtectedNetworkOnlyFile(filepath.Join(dir, "network-only-choice.json"), 65536)
	p.choiceOn = os.IsNotExist(err)
	if err == nil {
		p.choiceOn = networkOnlyDriverChoice(b)
	}
	r, err := readNetworkOnlyReceipt(dir)
	receiptMissing := os.IsNotExist(err)
	p.receiptValid = err == nil
	if err != nil && !(allowInitial && receiptMissing) || !p.choiceOn {
		return false, networkOnlyDriverUnproven
	}
	p.receiptOwnsRoot = networkOnlyDriverReceiptOwnsRoot(r.Nodes, root)
	current := Inspect()
	if !descriptorAttachment(before).same(descriptorAttachment(current)) {
		return false, networkOnlyDriverUnproven
	}
	p.officialHealthy, p.rootNativeHealthy = networkOnlyDriverRootHealthy(current, root)
	p.policyStart = networkOnlyServiceStartType(r.StartType)
	m, err := mgr.Connect()
	if err != nil {
		return false, networkOnlyDriverUnproven
	}
	defer m.Disconnect()
	service, err := m.OpenService("Apple Mobile Device Service")
	if err != nil {
		return false, networkOnlyDriverUnproven
	}
	defer service.Close()
	state, stateError := service.Query()
	cfg, configError := service.Config()
	p.serviceReadable = stateError == nil && configError == nil
	p.serviceState, p.serviceStart = uint32(state.State), cfg.StartType
	admitted := p.admitsExpectedStop() && state.State == svc.Stopped
	if allowInitial && receiptMissing {
		admitted = p.admitsInitialApply(true)
	}
	if !admitted || ctx.Err() != nil {
		return false, networkOnlyDriverUnproven
	}
	// A concurrent transition or owner-scope change invalidates the readback.
	networkOnly.Lock()
	unchanged := networkOnly.dir == dir && networkOnly.available && networkOnly.enabled && !networkOnly.busy && !networkOnly.pending && !networkOnly.blocked
	networkOnly.Unlock()
	ipadCandidateControl.Lock()
	unchanged = unchanged && ipadCandidateControl.stage == stage && strings.EqualFold(ipadCandidateControl.scope, root) && !ipadCandidateControl.busy && !ipadCandidateControl.pending && !ipadCandidateControl.blocked
	ipadCandidateControl.Unlock()
	latestRoot, latestProof := observedIPadModeProofs.scope()
	if !unchanged || !latestProof || !strings.EqualFold(latestRoot, root) {
		return false, networkOnlyDriverUnproven
	}
	return true, ""
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
