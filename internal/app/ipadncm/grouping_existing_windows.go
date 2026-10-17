//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"
	"suhang/usbnet/internal/diagnostics/grouptrial"
)

var existingGroupingDriverPattern = regexp.MustCompile(`(?i)^\{88BAE032-5A81-49F0-BC3D-A4FF138216D6\}\\[0-9]{4}$`)

func (b *groupingBackend) networkRoot() string {
	if b.existingTarget != nil {
		return b.existingTarget.root
	}
	return b.j.RootID
}
func (b *groupingBackend) networkDriver() string {
	if b.existingTarget != nil {
		return b.existingTarget.driver
	}
	return b.j.DriverKey
}

// Observes the current official driver association with query access only.
// No missing original is inferred and no grouping recovery record is created.
func readExistingNetworkTarget(root, expectedDriver string) (target existingNetworkTarget, problem string) {
	target.root = root
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\`+root, registry.QUERY_VALUE)
	if err != nil {
		return target, "EXISTING_GROUPING_ROOT_REGISTRY_UNAVAILABLE"
	}
	defer k.Close()
	driver, _, err := k.GetStringValue("Driver")
	if err != nil || !existingGroupingDriverPattern.MatchString(driver) || expectedDriver != "" && !strings.EqualFold(driver, expectedDriver) {
		return target, "EXISTING_GROUPING_DRIVER_ASSOCIATION_UNPROVEN"
	}
	target.driver = driver
	filters, _, err := k.GetStringsValue("LowerFilters")
	apple := false
	for _, filter := range filters {
		if strings.EqualFold(filter, "AppleLowerFilter") {
			apple = true
		}
	}
	if err != nil || !apple {
		return target, "EXISTING_GROUPING_APPLE_BINDING_UNPROVEN"
	}
	software, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\`+driver, registry.QUERY_VALUE)
	if err != nil {
		return target, "EXISTING_GROUPING_DRIVER_KEY_UNAVAILABLE"
	}
	defer software.Close()
	version, _, err := software.GetStringValue("DriverVersion")
	if err != nil || version != "486.0.0.0" {
		return target, "EXISTING_GROUPING_DRIVER_VERSION_UNSUPPORTED"
	}
	value, _, err := software.GetBinaryValue("EnumeratorClass")
	if err != nil || !bytes.Equal(value, groupingBytes) {
		return target, "EXISTING_GROUPING_VALUE_CHANGED"
	}
	return target, ""
}

func existingGroupingCMProof(s Snapshot, target existingNetworkTarget) (configuredStartupEvidence, string) {
	var nodes []configuredStartupCMNode
	for _, n := range s.Nodes {
		isRoot := strings.EqualFold(n.instanceID, target.root)
		if isRoot && n.DriverVersion != "486.0.0.0" {
			return configuredStartupEvidence{}, "EXISTING_GROUPING_ROOT_DRIVER_CHANGED"
		}
		belongs, problem := configuredStartupNodeScope(n, target.root)
		if problem != "" {
			return configuredStartupEvidence{}, problem
		}
		nodes = append(nodes, configuredStartupCMNode{Prefix: n.IDPrefix, Service: n.Service, StateError: n.StateError, Status: n.DevNodeStatus, EnumeratorClass: n.EnumeratorClass, Problem: n.Problem, Root: isRoot, ScopeProven: belongs})
	}
	proof := configuredStartupCMProof(nodes)
	return proof, configuredCMFailureReason(proof)
}

// Also used by every fresh peer/active mapping in this branch. A cached initial
// proof never permits continuing on changed CM nodes or a reassigned NIC.
func (b *groupingBackend) existingNetworkMapping(s Snapshot, expected string, readAdapters func() []NetworkAdapter) (NetworkAdapter, string) {
	if s.Error != "" || b.existingTarget == nil {
		return NetworkAdapter{}, "EXISTING_GROUPING_NATIVE_SNAPSHOT_UNAVAILABLE"
	}
	if _, problem := readExistingNetworkTarget(b.existingTarget.root, b.existingTarget.driver); problem != "" {
		return NetworkAdapter{}, problem
	}
	if _, problem := existingGroupingCMProof(s, *b.existingTarget); problem != "" {
		return NetworkAdapter{}, problem
	}
	adapters := readAdapters()
	observations := make([]startupAdapterObservation, 0, len(adapters))
	for _, a := range adapters {
		observations = append(observations, startupAdapterObservation{Matched: a.Matched, StatisticsRead: a.StatisticsRead, Error: a.Error, OperStatus: a.OperStatus, MediaState: a.MediaConnectState})
	}
	if !uniqueOperationalStartupMapping(observations) {
		return NetworkAdapter{}, "EXISTING_GROUPING_UNIQUE_OPERATIONAL_MAPPING_REQUIRED"
	}
	for _, a := range adapters {
		if a.OperStatus == 1 && a.MediaConnectState == 1 {
			if expected != "" && a.key != expected {
				return NetworkAdapter{}, "PEER_ADAPTER_IDENTITY_CHANGED"
			}
			if _, problem := readExistingNetworkTarget(b.existingTarget.root, b.existingTarget.driver); problem != "" {
				return NetworkAdapter{}, problem
			}
			return a, ""
		}
	}
	return NetworkAdapter{}, "EXISTING_GROUPING_UNIQUE_OPERATIONAL_MAPPING_REQUIRED"
}

// Handles an already grouped device without taking ownership of its registry
// configuration. Only the ordinary application session can create network
// changes, with its unchanged intent, original-value and cleanup checks.
func RunExistingGrouping(version, dir, system string, mode Result, consent func() bool) (r GroupingResult, handled bool) {
	ctx := connectionContext()
	s := Inspect()
	root := exactIPadRoot(s)
	for _, n := range s.Nodes {
		if strings.EqualFold(n.IDPrefix, `USB\VID_05AC&PID_12AB`) && n.EnumeratorClass == "020000" {
			handled = true
		}
	}
	if !handled {
		return
	}
	r.Before = s
	r.Transaction = grouptrial.Report{Status: "EXISTING_GROUPING_OBSERVED_NO_WRITE_OR_RESTART"}
	attempt := currentSoftwareAttempt()
	recordGroupingReuse(attempt, root != "", "EXISTING_LAYOUT_VERIFYING")
	fail := func(problem string) (GroupingResult, bool) {
		r.Transaction.Error = problem
		recordGroupingReuse(attempt, root != "", "EXISTING_LAYOUT_REJECTED")
		return r, true
	}
	admission := existingGroupingAdmission{ContextActive: ctx != nil && ctx.Err() == nil, CurrentRoot: root != "" && networkOnlyUSBEligible(s) && sameRootInstance(mode.Before, s) && HasActiveNCM(s) && modeResultIdentity(mode, true)}
	if !admission.ContextActive || !admission.CurrentRoot {
		return fail("EXISTING_GROUPING_CURRENT_ROOT_OR_CONTEXT_UNPROVEN")
	}
	admission.Consent = consent != nil && consent()
	if !admission.Consent {
		return fail("EXISTING_GROUPING_CURRENT_CONSENT_REQUIRED")
	}
	_, _, receiptError := readStartupOwnedGrouping(dir, root)
	admission.ReceiptsAbsent = os.IsNotExist(receiptError)
	if !admission.ReceiptsAbsent {
		return fail("EXISTING_GROUPING_RECEIPT_STATE_CHANGED")
	}
	target, problem := readExistingNetworkTarget(root, "")
	if problem != "" {
		return fail(problem)
	}
	admission.Driver = true
	admission.CM, problem = existingGroupingCMProof(s, target)
	if problem != "" {
		return fail(problem)
	}
	b := &groupingBackend{version: version, dir: dir, system: system, mode: mode, result: &r, applicationConsent: consent, existingTarget: &target}
	_, problem = b.existingNetworkMapping(s, "", func() []NetworkAdapter { return readNCMAdapters(s) })
	if problem != "" {
		return fail(problem)
	}
	admission.Mapping = true
	_, _, receiptError = readStartupOwnedGrouping(dir, root)
	admission.ReceiptsAbsent, admission.ContextActive = os.IsNotExist(receiptError), ctx.Err() == nil
	if problem = admission.failure(); problem != "" {
		return fail(problem)
	}
	r.GroupingObserved, r.NativeStartedNodes = true, admission.CM.StartedControls
	r.Transaction.Observation = "EXISTING_OPERATIONAL_TOPOLOGY_PROVEN_NO_GROUPING_OWNERSHIP"
	recordConnectionStage("native_ncm_started", "live_existing_grouping_no_registry_ownership")
	network := b.observeNetwork()
	r.NetworkObservation = &network
	peer := b.waitForPeerReady()
	r.PeerProbe = &peer
	recordGroupingReuse(attempt, true, "EXISTING_LAYOUT_VERIFIED_SESSION_STARTING")
	app := b.runApplication(peer)
	r.Application = &app
	recordGroupingReuse(attempt, true, "EXISTING_LAYOUT_SESSION_RETURNED")
	if b.applicationRestoreError != "" {
		r.Transaction.Error, r.Transaction.RestoreError = b.applicationRestoreError, b.applicationRestoreError
	}
	return
}
