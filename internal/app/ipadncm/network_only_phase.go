package ipadncm

import (
	"sync"
	"time"
)

// Explicit diagnostic only: default off, one attempt, bounded total native
// observation time. It cannot grant device policy or pairing authorization.
type networkOnlyPhaseCapture struct {
	sync.Mutex
	expires    time.Time
	attempt    uint64
	remaining  time.Duration
	inProgress bool
}

type NetworkOnlyPhaseCaptureState struct {
	Enabled     bool   `json:"enabled_default_off"`
	Attempt     uint64 `json:"single_selected_attempt"`
	RemainingMS int64  `json:"remaining_cumulative_observation_budget_ms"`
	InProgress  bool   `json:"observation_in_progress"`
	TimingScope string `json:"timing_scope"`
}

var phaseCapture networkOnlyPhaseCapture

func (c *networkOnlyPhaseCapture) set(enabled bool, now time.Time) {
	c.Lock()
	defer c.Unlock()
	if !enabled {
		c.expires = time.Time{}
		return
	}
	// A re-arm during a native call cannot reset its budget or attempt.
	if c.inProgress {
		return
	}
	c.expires, c.attempt, c.remaining = now.Add(120*time.Second), 0, 2*time.Second
}

func (c *networkOnlyPhaseCapture) begin(attempt uint64, now time.Time) (time.Duration, bool) {
	c.Lock()
	defer c.Unlock()
	if attempt == 0 || !now.Before(c.expires) || c.inProgress || c.remaining <= 0 || (c.attempt != 0 && c.attempt != attempt) {
		return 0, false
	}
	c.attempt, c.inProgress = attempt, true
	return c.remaining, true
}

func (c *networkOnlyPhaseCapture) finish(elapsed time.Duration) {
	c.Lock()
	defer c.Unlock()
	c.remaining = max(0, c.remaining-elapsed)
	c.inProgress = false
}

func (c *networkOnlyPhaseCapture) active(now time.Time) bool {
	c.Lock()
	defer c.Unlock()
	return now.Before(c.expires) && c.remaining > 0
}

func (c *networkOnlyPhaseCapture) state(now time.Time) NetworkOnlyPhaseCaptureState {
	c.Lock()
	defer c.Unlock()
	return NetworkOnlyPhaseCaptureState{Enabled: now.Before(c.expires) && c.remaining > 0, Attempt: c.attempt, RemainingMS: c.remaining.Milliseconds(), InProgress: c.inProgress, TimingScope: "diagnostic changes startup timing; budget checked between synchronous native calls, not a preemptive OS deadline"}
}

func SetNetworkOnlyPhaseCapture(enabled bool) NetworkOnlyPhaseCaptureState {
	phaseCapture.set(enabled, time.Now())
	return NetworkOnlyPhaseCaptureStatus()
}

func NetworkOnlyPhaseCaptureStatus() NetworkOnlyPhaseCaptureState {
	return phaseCapture.state(time.Now())
}

// These are observations at an Ensure call, not continuous isolation or trust
// prompt attribution. A complete empty PRESENT inventory is distinct from an
// unreadable inventory and from ALL-class observations of owned old instances.
type NetworkOnlyPhaseNode struct {
	Digest  string                  `json:"node_id_sha256"`
	Class   string                  `json:"class_guid"`
	Matches int                     `json:"exact_all_instance_matches"`
	Native  PortableNodeObservation `json:"native_observation"`
}

type NetworkOnlyPhaseDiagnostic struct {
	Attempt             uint64                 `json:"attempt"`
	ElapsedMS           int64                  `json:"ms_since_software_attempt_not_physical_insertion"`
	ObservedUTC         string                 `json:"observed_utc"`
	ObservationMS       int64                  `json:"native_observation_duration_ms"`
	ObservationError    string                 `json:"observation_error,omitempty"`
	Phase               string                 `json:"phase"`
	Point               string                 `json:"point"`
	Outcome             string                 `json:"ensure_outcome"`
	DescriptorBound     bool                   `json:"same_current_descriptor_and_native_root_bound"`
	Configuration       byte                   `json:"current_configuration"`
	PTPDescriptor       bool                   `json:"selected_configuration_has_ptp_interface"`
	ServiceReadable     bool                   `json:"amds_readable"`
	ServiceState        uint32                 `json:"amds_state"`
	ServiceStartType    uint32                 `json:"amds_start_type"`
	PresentComplete     bool                   `json:"all_enumerator_present_portable_inventory_complete"`
	InventoryFromEnsure bool                   `json:"inventory_is_the_actual_ensure_enumeration"`
	PresentCount        *int                   `json:"present_portable_count"`
	PresentEmpty        bool                   `json:"complete_present_inventory_is_empty"`
	PresentError        string                 `json:"present_inventory_error,omitempty"`
	ReceiptValid        bool                   `json:"owned_receipt_valid"`
	OwnedCount          *int                   `json:"owned_current_root_count"`
	OwnedError          string                 `json:"owned_inventory_error,omitempty"`
	AllComplete         bool                   `json:"all_instance_enumeration_complete"`
	AllError            string                 `json:"all_instance_enumeration_error,omitempty"`
	RootMatches         int                    `json:"exact_root_all_instance_matches"`
	RootCMClassGUID     string                 `json:"root_cm_class_guid,omitempty"`
	RootSetupClassGUID  string                 `json:"root_setup_class_guid,omitempty"`
	RootClassCR         uint32                 `json:"root_class_cr"`
	RootClassType       uint32                 `json:"root_class_property_type"`
	RootClassSize       uint32                 `json:"root_class_property_size"`
	PresentOmitted      int                    `json:"present_observations_omitted"`
	OwnedOmitted        int                    `json:"owned_observations_omitted"`
	PresentNodes        []NetworkOnlyPhaseNode `json:"present_inventory_native_observations"`
	OwnedNodes          []NetworkOnlyPhaseNode `json:"owned_all_native_observations_not_present_inventory"`
}

type networkOnlyPhaseHistory struct {
	sync.Mutex
	recent []NetworkOnlyPhaseDiagnostic
}

var networkOnlyPhases networkOnlyPhaseHistory

func copyNetworkOnlyPhase(d NetworkOnlyPhaseDiagnostic) NetworkOnlyPhaseDiagnostic {
	if d.PresentCount != nil {
		n := *d.PresentCount
		d.PresentCount = &n
	}
	if d.OwnedCount != nil {
		n := *d.OwnedCount
		d.OwnedCount = &n
	}
	d.PresentNodes = append([]NetworkOnlyPhaseNode(nil), d.PresentNodes...)
	d.OwnedNodes = append([]NetworkOnlyPhaseNode(nil), d.OwnedNodes...)
	return d
}

func (h *networkOnlyPhaseHistory) record(d NetworkOnlyPhaseDiagnostic) {
	// The native collector caps queries as well; this protects the public store.
	if len(d.PresentNodes) > 16 {
		d.PresentOmitted += len(d.PresentNodes) - 16
		d.PresentNodes = d.PresentNodes[:16]
	}
	if len(d.OwnedNodes) > 16 {
		d.OwnedOmitted += len(d.OwnedNodes) - 16
		d.OwnedNodes = d.OwnedNodes[:16]
	}
	h.Lock()
	defer h.Unlock()
	if len(h.recent) == 32 {
		h.recent = h.recent[1:]
	}
	h.recent = append(h.recent, copyNetworkOnlyPhase(d))
}

func (h *networkOnlyPhaseHistory) snapshot() []NetworkOnlyPhaseDiagnostic {
	h.Lock()
	defer h.Unlock()
	out := make([]NetworkOnlyPhaseDiagnostic, len(h.recent))
	for i, d := range h.recent {
		out[i] = copyNetworkOnlyPhase(d)
	}
	return out
}

func NetworkOnlyPhaseDiagnostics() []NetworkOnlyPhaseDiagnostic {
	return networkOnlyPhases.snapshot()
}

func (d *NetworkOnlyPhaseDiagnostic) setPresentInventory(count int, complete bool) {
	d.PresentComplete = complete
	d.PresentCount = nil
	d.PresentEmpty = false
	if complete {
		d.PresentCount = new(int)
		*d.PresentCount = count
		d.PresentEmpty = count == 0
	}
}
