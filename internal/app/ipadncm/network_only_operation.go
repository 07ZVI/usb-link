package ipadncm

import (
	"fmt"
	"sync"
	"time"
)

// cfgmgr32.h (Microsoft SDK): UI_NOT_OK=0x04 and PERSIST=0x08.
// Values 0x01/0x02 are ABSOLUTE/HARDWARE, not these documented flags.
const portableDisableUINotOK = uint32(0x04)
const portableDisablePersist = uint32(0x08)
const portableDisableFlags = portableDisableUINotOK | portableDisablePersist

// The settings choice is distinct from successful application to a live node.
// A failed application must stop new attempts until an explicit recovery/retry.
type networkOnlyOperationState struct {
	blocked        bool
	status, notice string
}

func (s *networkOnlyOperationState) fail(err error) {
	if err != nil {
		s.blocked, s.status, s.notice = true, "ERROR", err.Error()
	}
}

type PortableNodeObservation struct {
	InstanceMatches bool   `json:"same_instance_verified"`
	ClassMatches    bool   `json:"same_class_verified"`
	RootMatches     bool   `json:"same_usb_root_verified"`
	StateReadable   bool   `json:"cm_state_readable"`
	FlagsReadable   bool   `json:"cm_config_flags_readable"`
	StateCR         uint32 `json:"cm_state_cr"`
	FlagsCR         uint32 `json:"cm_config_flags_cr"`
	InstanceCR      uint32 `json:"cm_instance_cr"`
	ClassCR         uint32 `json:"cm_class_cr"`
	FlagsType       uint32 `json:"cm_config_flags_type"`
	FlagsSize       uint32 `json:"cm_config_flags_size"`
	FlagsAbsent     bool   `json:"cm_config_flags_absent"`
	Status          uint32 `json:"cm_devnode_status"`
	Problem         uint32 `json:"cm_problem"`
	ConfigFlags     uint32 `json:"cm_config_flags"`
	Error           string `json:"read_error,omitempty"`
}

func (s PortableNodeObservation) proofError(original uint32) error {
	switch {
	case !s.InstanceMatches || !s.ClassMatches || !s.RootMatches:
		return fmt.Errorf("portable instance/class/root ownership unproven")
	case !s.StateReadable || !s.FlagsReadable:
		return fmt.Errorf("portable native state/property unreadable")
	case s.Status&0x100 != 0: // DN_NEED_RESTART
		return fmt.Errorf("portable node requires Windows restart")
	case s.ConfigFlags != original && s.ConfigFlags != original|1:
		return fmt.Errorf("portable configuration ownership changed")
	default:
		return nil
	}
}
func (s PortableNodeObservation) targetReadBack(original uint32, disabled bool) bool {
	if s.proofError(original) != nil {
		return false
	}
	if disabled {
		return s.Problem == 22 && s.Status&8 == 0 && s.ConfigFlags == original|1
	}
	return s.Problem != 22 && s.ConfigFlags == original
}

type PortableNodeOperationDiagnostic struct {
	StartedUTC               string                  `json:"started_utc"`
	NodePrefix               string                  `json:"node_id_prefix"`
	Class                    string                  `json:"class_guid"`
	Disabled                 bool                    `json:"requested_disabled"`
	OriginalConfigFlags      uint32                  `json:"original_config_flags"`
	Before                   PortableNodeObservation `json:"before"`
	After                    PortableNodeObservation `json:"after"`
	ChangeAttempted          bool                    `json:"change_attempted"`
	ChangeCR                 uint32                  `json:"change_cr"`
	ChangeFlags              uint32                  `json:"change_flags"`
	RelocateCR               uint32                  `json:"cm_relocate_cr"`
	DevInstChanged           bool                    `json:"devinst_changed"`
	Outcome                  string                  `json:"outcome"`
	PhantomPropertyRestore   bool                    `json:"phantom_property_restore"`
	OriginalPresenceUnknown  bool                    `json:"original_presence_unknown"`
	OriginalPresenceVerified bool                    `json:"original_presence_verified"`
	RecordedValueRestored    bool                    `json:"recorded_original_value_verified"`
	ElapsedMS                int64                   `json:"elapsed_ms"`
}
type portableOperationHistory struct {
	sync.Mutex
	recent []PortableNodeOperationDiagnostic
}

var networkOnlyOperationHistory portableOperationHistory

func (h *portableOperationHistory) record(d PortableNodeOperationDiagnostic) {
	h.Lock()
	defer h.Unlock()
	if len(h.recent) == 8 {
		h.recent = h.recent[1:]
	}
	h.recent = append(h.recent, d)
}
func (h *portableOperationHistory) snapshot() []PortableNodeOperationDiagnostic {
	h.Lock()
	defer h.Unlock()
	return append([]PortableNodeOperationDiagnostic(nil), h.recent...)
}

// Cached results of actual operations only: no polls, property queries or paths.
func NetworkOnlyOperationDiagnostics() []PortableNodeOperationDiagnostic {
	return networkOnlyOperationHistory.snapshot()
}
func beginPortableOperation(n portableNodeReceipt, disabled bool) (PortableNodeOperationDiagnostic, time.Time) {
	return PortableNodeOperationDiagnostic{StartedUTC: time.Now().UTC().Format(time.RFC3339), NodePrefix: portableNodePrefix(n.ID), Class: n.Class, Disabled: disabled, OriginalConfigFlags: n.ConfigFlags}, time.Now()
}

// Prune only a node whose exact native restoration has succeeded, then commit
// that fact durably before touching the next node. The v1 receipt stays readable
// by older releases; unverified nodes and originally disabled nodes remain.
func restorePortableNodeReceipts(nodes []portableNodeReceipt, restore func(portableNodeReceipt) error, checkpoint func([]portableNodeReceipt) error) error {
	remaining := append([]portableNodeReceipt(nil), nodes...)
	for {
		index := -1
		for i, n := range remaining {
			if !n.OriginalDisabled {
				index = i
				break
			}
		}
		if index < 0 {
			return nil
		}
		if err := restore(remaining[index]); err != nil {
			return err
		}
		next := append([]portableNodeReceipt(nil), remaining[:index]...)
		next = append(next, remaining[index+1:]...)
		if err := checkpoint(next); err != nil {
			return err
		}
		remaining = next
	}
}
