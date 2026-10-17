package ipadncm

import (
	"strconv"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"sync"
)

// This is an additional proof for a committed layout or an exact protected
// product pending layout, both with complete live CM/root/adapter ownership.
// It does not change the generic predicate or admit networking on its own.
type configuredStartupEvidence struct {
	ReceiptValid        bool `json:"receipt_valid"`
	RegistryOwned       bool `json:"registry_owned"`
	SameUSBRoot         bool `json:"same_usb_root"`
	RootHealthy         bool `json:"root_healthy"`
	NodesReadable       bool `json:"all_node_cm_states_readable"`
	NoRestart           bool `json:"no_node_requires_restart"`
	ControlTopology     bool `json:"exact_two_controls_no_orphan_data"`
	AllControlsSameRoot bool `json:"controls_belong_to_same_root"`
	StartedControls     int  `json:"started_controls"`
	MappingVerified     bool `json:"unique_operational_ncm_mapping_verified"`
}

func (e configuredStartupEvidence) ready() bool {
	return e.ReceiptValid && e.RegistryOwned && e.SameUSBRoot && e.RootHealthy && e.NodesReadable && e.NoRestart && e.ControlTopology && e.AllControlsSameRoot && e.StartedControls >= 1 && e.StartedControls <= 2 && e.MappingVerified
}

type StartupDiagnosticNode struct {
	NodePrefix         string `json:"node_id_prefix"`
	Service            string `json:"service"`
	Problem            uint32 `json:"problem"`
	StateError         string `json:"cm_state_error,omitempty"`
	ProblemStatus      string `json:"problem_status,omitempty"`
	ProblemStatusError string `json:"problem_status_error,omitempty"`
	DevNodeStatus      string `json:"cm_devnode_status,omitempty"`
	StatusReadable     bool   `json:"cm_status_readable"`
	Started            bool   `json:"dn_started"`
	NeedsRestart       bool   `json:"dn_need_restart"`
}
type StartupDiagnosticSample struct {
	ElapsedMS       int64                     `json:"elapsed_ms"`
	Controls        int                       `json:"controls"`
	StartedControls int                       `json:"started_controls"`
	FailedControls  int                       `json:"failed_controls"`
	OrphanData      int                       `json:"orphan_data"`
	UngroupedRoot   bool                      `json:"ungrouped_root_confirmed"`
	GenericSettled  bool                      `json:"generic_predicate_settled"`
	ConfiguredProof configuredStartupEvidence `json:"configured_proof"`
	FastPathReason  string                    `json:"fast_path_reason"`
	Nodes           []StartupDiagnosticNode   `json:"nodes"`
	NodesTruncated  bool                      `json:"nodes_truncated"`
}
type StartupReadinessDiagnostic struct {
	Attempt             uint64                    `json:"software_attempt"`
	StartedUTC          string                    `json:"started_utc"`
	CheckKind           string                    `json:"check_kind"`
	EventMode           bool                      `json:"event_mode"`
	EventSubscribeError string                    `json:"event_subscribe_error,omitempty"`
	Status              string                    `json:"status"`
	ExitReason          string                    `json:"exit_reason"`
	FastPathQualified   bool                      `json:"fast_path_qualified"`
	FastPathReason      string                    `json:"fast_path_reason"`
	ElapsedMS           int64                     `json:"elapsed_ms"`
	SampleCount         int                       `json:"sample_count"`
	SamplesOmitted      int                       `json:"samples_omitted"`
	Samples             []StartupDiagnosticSample `json:"samples"`
}

// Keep first 3 and latest 9 samples. These are summaries of existing inventory
// reads, never an additional polling loop, and contain no full USB identities.
func (d *StartupReadinessDiagnostic) add(s StartupDiagnosticSample) {
	d.SampleCount++
	if len(d.Samples) == 12 {
		copy(d.Samples[3:], d.Samples[4:])
		d.Samples = d.Samples[:11]
		d.SamplesOmitted++
	}
	d.Samples = append(d.Samples, s)
}

type startupDiagnosticHistory struct {
	sync.Mutex
	recent []StartupReadinessDiagnostic
}

var startupReadinessHistory startupDiagnosticHistory

func cloneStartupReadinessDiagnostic(d StartupReadinessDiagnostic) StartupReadinessDiagnostic {
	d.Samples = append([]StartupDiagnosticSample(nil), d.Samples...)
	for i := range d.Samples {
		d.Samples[i].Nodes = append([]StartupDiagnosticNode(nil), d.Samples[i].Nodes...)
	}
	return d
}
func (h *startupDiagnosticHistory) record(d StartupReadinessDiagnostic) {
	h.Lock()
	defer h.Unlock()
	if len(h.recent) == 2 {
		h.recent = h.recent[1:]
	}
	h.recent = append(h.recent, cloneStartupReadinessDiagnostic(d))
}
func (h *startupDiagnosticHistory) snapshot() []StartupReadinessDiagnostic {
	h.Lock()
	defer h.Unlock()
	out := make([]StartupReadinessDiagnostic, len(h.recent))
	for i, d := range h.recent {
		out[i] = cloneStartupReadinessDiagnostic(d)
	}
	return out
}

func StartupReadinessDiagnostics() []StartupReadinessDiagnostic {
	return startupReadinessHistory.snapshot()
}

// Raw CM observations allow tests to exercise real status/problem combinations,
// instead of treating “one started” as a substitute for a complete topology.
type configuredStartupCMNode struct {
	Prefix, Service, StateError, Status, EnumeratorClass string
	Problem                                              uint32
	Root, ScopeProven                                    bool
}

// Parse a hardware-ID prefix as complete USB tokens. Revision and CDC tokens
// are qualifiers, not part of the interface number; unknown/duplicate tokens,
// instance suffixes, partial hex values and a nonfinal MI token are rejected.
func configuredUSBInterface(prefix string) (mi string, valid bool) {
	parts := strings.Split(strings.ToUpper(prefix), `\`)
	if len(parts) != 2 || parts[0] != "USB" {
		return "", false
	}
	tokens := strings.Split(parts[1], "&")
	if len(tokens) < 2 || tokens[0] != "VID_05AC" || tokens[1] != "PID_12AB" {
		return "", false
	}
	seen := map[string]bool{}
	for i, token := range tokens[2:] {
		key, value, ok := strings.Cut(token, "_")
		if !ok || seen[key] {
			return "", false
		}
		seen[key] = true
		width := 0
		switch key {
		case "REV":
			width = 4
		case "CDC":
			width = 2
			if value != "0D" {
				return "", false
			}
		case "MI":
			width = 2
			if i != len(tokens[2:])-1 {
				return "", false
			}
			mi = value
		default:
			return "", false
		}
		if len(value) != width {
			return "", false
		}
		for _, c := range value {
			if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
				return "", false
			}
		}
	}
	if seen["CDC"] && mi == "" {
		return "", false
	}
	return mi, true
}

func configuredStartupCMProof(nodes []configuredStartupCMNode) (e configuredStartupEvidence) {
	e.NodesReadable, e.NoRestart, e.AllControlsSameRoot = len(nodes) > 0, true, true
	roots, controls, mi02, mi04 := 0, 0, 0, 0
	layoutValid, orphan := true, false
	interfaces := map[string]bool{}
	for _, n := range nodes {
		_, err := strconv.ParseUint(n.Status, 0, 32)
		if n.StateError != "" || err != nil {
			e.NodesReadable = false
		}
		if grouptrial.NeedsWindowsRestart(n.Status) {
			e.NoRestart = false
		}
		mi, valid := configuredUSBInterface(n.Prefix)
		if !valid {
			layoutValid = false
		}
		if n.Root {
			roots++
			// Root identity still uses the original exact composite root ID.
			e.RootHealthy = strings.EqualFold(n.Prefix, `USB\VID_05AC&PID_12AB`) && strings.EqualFold(n.Service, "usbccgp") && n.EnumeratorClass == "020000" && grouptrial.NativeStartObserved(n.Problem, n.StateError, n.Status)
			continue
		}
		// Root relationship comes only from the native CM parent chain, never
		// from the VID/PID/interface text or a layout parse failure.
		if !n.ScopeProven {
			e.AllControlsSameRoot = false
		}
		if !valid || mi == "" {
			layoutValid = false
		}
		if interfaces[mi] {
			layoutValid = false
		}
		interfaces[mi] = true
		if mi == "03" || mi == "05" {
			orphan = true
		}
		if !strings.EqualFold(n.Service, "UsbNcm") {
			continue
		}
		controls++
		if grouptrial.NativeStartObserved(n.Problem, n.StateError, n.Status) {
			e.StartedControls++
		}
		switch mi {
		case "02":
			mi02++
		case "04":
			mi04++
		default:
			layoutValid = false
		}
	}
	e.RootHealthy = roots == 1 && e.RootHealthy
	e.ControlTopology = layoutValid && controls == 2 && mi02 == 1 && mi04 == 1 && !orphan
	return
}

func configuredCMFailureReason(e configuredStartupEvidence) string {
	switch {
	case !e.RootHealthy:
		return "CONFIGURED_CM_ROOT_NOT_HEALTHY"
	case !e.NodesReadable:
		return "CONFIGURED_CM_NODE_STATE_UNREADABLE"
	case !e.NoRestart:
		return "CONFIGURED_CM_NODE_RESTART_REQUIRED"
	case !e.AllControlsSameRoot:
		return "CONFIGURED_CM_NODE_ROOT_RELATIONSHIP_UNPROVEN"
	case !e.ControlTopology:
		return "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID"
	case e.StartedControls < 1:
		return "CONFIGURED_CM_NO_STARTED_CONTROL"
	default:
		return ""
	}
}

type startupAdapterObservation struct {
	Matched, StatisticsRead bool
	Error                   string
	OperStatus, MediaState  uint32
}

func uniqueOperationalStartupMapping(adapters []startupAdapterObservation) bool {
	if len(adapters) == 0 {
		return false
	}
	operational := 0
	for _, a := range adapters {
		if !a.Matched || !a.StatisticsRead || a.Error != "" {
			return false
		}
		if a.OperStatus == 1 && a.MediaState == 1 {
			operational++
		}
	}
	return operational == 1
}
