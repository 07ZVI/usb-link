//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"strconv"
	"strings"
	"unsafe"

	"suhang/usbnet/internal/diagnostics/grouptrial"
)

func configuredStartupRegistryOwned(j groupingJournal) bool {
	k, problem := groupingOwnedKey(j, registry.QUERY_VALUE)
	if problem != "" {
		return false
	}
	defer k.Close()
	v, _, e := k.GetBinaryValue("EnumeratorClass")
	return e == nil && bytes.Equal(v, groupingBytes)
}

func nodeCMReadable(n Node) bool {
	_, e := strconv.ParseUint(n.DevNodeStatus, 0, 32)
	return n.StateError == "" && e == nil
}

func configuredStartupNodeScope(n Node, root string) (bool, string) {
	if n.devInst == 0 || n.instanceID == "" {
		return false, "CONFIGURED_CM_NODE_INSTANCE_UNAVAILABLE"
	}
	var id [1024]uint16
	cr, _, _ := portableID.Call(uintptr(n.devInst), uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)), 0)
	if cr != 0 {
		return false, "CONFIGURED_CM_NODE_INSTANCE_UNREADABLE"
	}
	if !strings.EqualFold(windows.UTF16ToString(id[:]), n.instanceID) {
		return false, "CONFIGURED_CM_NODE_INSTANCE_CHANGED"
	}
	if strings.EqualFold(n.instanceID, root) {
		return true, ""
	}
	belongs, err := descendantOfPortableRoot(n.devInst, root)
	if err != nil {
		return false, "CONFIGURED_CM_PARENT_CHAIN_UNREADABLE"
	}
	if !belongs {
		return false, "CONFIGURED_CM_NODE_ON_DIFFERENT_ROOT"
	}
	return true, ""
}

// Only a durable, owned grouping receipt can authorize this additional wait
// completion. It grants no routes, permissions or network readiness on its own.
func configuredStartupProof(ctx context.Context, dir string, mode Result, s Snapshot, readiness startupReadiness) (e configuredStartupEvidence, reason string) {
	e.StartedControls = readiness.StartedControls
	if dir == "" || !IPadCandidateFeatures().PersistentGrouping || !IPadCandidateFeatures().EventStartup {
		return e, "CONFIGURED_PROOF_NOT_ENABLED"
	}
	root := exactIPadRoot(s)
	j, pending, err := readStartupOwnedGrouping(dir, root)
	if err != nil {
		return e, "CONFIGURED_RECEIPT_UNAVAILABLE_OR_INVALID"
	}
	e.ReceiptValid = true
	e.SameUSBRoot = root != "" && strings.EqualFold(j.RootID, root) && sameRootInstance(mode.Before, s) && modeResultIdentity(mode, true)
	if !e.SameUSBRoot {
		return e, "CONFIGURED_ROOT_OR_MODE_IDENTITY_CHANGED"
	}
	e.RegistryOwned = configuredStartupRegistryOwned(j)
	if !e.RegistryOwned {
		return e, "CONFIGURED_REGISTRY_NOT_OWNED"
	}
	var cmNodes []configuredStartupCMNode
	var scopeReason string
	for _, n := range s.Nodes {
		isRoot := strings.EqualFold(n.instanceID, root)
		belongs, problem := configuredStartupNodeScope(n, root)
		if problem != "" && scopeReason == "" {
			scopeReason = problem
		}
		cmNodes = append(cmNodes, configuredStartupCMNode{Prefix: n.IDPrefix, Service: n.Service, StateError: n.StateError, Status: n.DevNodeStatus, EnumeratorClass: n.EnumeratorClass, Problem: n.Problem, Root: isRoot, ScopeProven: belongs})
	}
	cm := configuredStartupCMProof(cmNodes)
	e.RootHealthy, e.NodesReadable, e.NoRestart, e.ControlTopology, e.AllControlsSameRoot = cm.RootHealthy, cm.NodesReadable, cm.NoRestart, cm.ControlTopology, cm.AllControlsSameRoot
	e.ControlTopology = e.ControlTopology && readiness.Controls == 2 && readiness.OrphanData == 0 && cm.StartedControls == readiness.StartedControls
	if scopeReason != "" {
		e.AllControlsSameRoot = false
		return e, scopeReason
	}
	if problem := configuredCMFailureReason(e); problem != "" {
		return e, problem
	}
	adapters := readNCMAdapters(s)
	// Refuse unreadable mappings instead of hiding a possible second NIC.
	observations := make([]startupAdapterObservation, 0, len(adapters))
	for _, a := range adapters {
		observations = append(observations, startupAdapterObservation{Matched: a.Matched, StatisticsRead: a.StatisticsRead, Error: a.Error, OperStatus: a.OperStatus, MediaState: a.MediaConnectState})
	}
	if !uniqueOperationalStartupMapping(observations) {
		return e, "CONFIGURED_NCM_MAPPING_NOT_UNIQUE_OR_UNREADABLE"
	}
	b := groupingBackend{j: j, mode: mode}
	_, problem := b.mappedPeerAdapterFrom(s, "", func() []NetworkAdapter { return adapters })
	if problem != "" {
		return e, "CONFIGURED_NCM_MAPPING_NOT_UNIQUE_OPERATIONAL"
	}
	// Registry/receipt ownership may change during native adapter mapping.
	fresh, freshPending, err := readStartupOwnedGrouping(dir, root)
	if err != nil || fresh != j || freshPending != pending || !configuredStartupRegistryOwned(j) || ctx.Err() != nil {
		e.RegistryOwned = false
		return e, "CONFIGURED_OWNERSHIP_CHANGED_DURING_MAPPING"
	}
	e.MappingVerified = true
	if pending {
		return e, "OWNED_PRODUCT_PENDING_OPERATIONAL_TOPOLOGY_PROVEN"
	}
	return e, "CONFIGURED_OPERATIONAL_TOPOLOGY_PROVEN"
}

func startupReadinessFromSnapshot(s Snapshot) (r startupReadiness) {
	for _, n := range s.Nodes {
		if n.IDPrefix == `USB\VID_05AC&PID_12AB` && strings.EqualFold(n.Service, "usbccgp") && n.Problem == 0 && n.StateError == "" && n.DriverVersion == "486.0.0.0" && n.EnumeratorError == "WIN32_2" && !grouptrial.NeedsWindowsRestart(n.DevNodeStatus) {
			r.UngroupedRootConfirmed = true
		}
		if strings.EqualFold(n.Service, "UsbNcm") {
			r.Controls++
			if grouptrial.NativeStartObserved(n.Problem, n.StateError, n.DevNodeStatus) {
				r.StartedControls++
			}
			if n.Problem == 10 && n.StateError == "" {
				r.FailedControls++
			}
		}
		if (strings.HasSuffix(n.IDPrefix, "&MI_03") || strings.HasSuffix(n.IDPrefix, "&MI_05")) && n.Service == "" && n.Problem == 28 && n.StateError == "" {
			r.OrphanData++
		}
	}
	return
}

func startupDiagnosticSample(s Snapshot, elapsed int64, readiness startupReadiness, proof configuredStartupEvidence, reason string) StartupDiagnosticSample {
	out := StartupDiagnosticSample{ElapsedMS: elapsed, Controls: readiness.Controls, StartedControls: readiness.StartedControls, FailedControls: readiness.FailedControls, OrphanData: readiness.OrphanData, UngroupedRoot: readiness.UngroupedRootConfirmed, GenericSettled: readiness.settled(), ConfiguredProof: proof, FastPathReason: reason}
	for _, n := range s.Nodes {
		if len(out.Nodes) == 12 {
			out.NodesTruncated = true
			break
		}
		out.Nodes = append(out.Nodes, StartupDiagnosticNode{NodePrefix: n.IDPrefix, Service: n.Service, Problem: n.Problem, StateError: n.StateError, ProblemStatus: n.ProblemStatus, ProblemStatusError: n.ProblemStatusError, DevNodeStatus: n.DevNodeStatus, StatusReadable: nodeCMReadable(n), Started: grouptrial.NativeStartObserved(n.Problem, n.StateError, n.DevNodeStatus), NeedsRestart: grouptrial.NeedsWindowsRestart(n.DevNodeStatus)})
	}
	return out
}
