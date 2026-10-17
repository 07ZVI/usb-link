//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"strings"
	"sync"
)

type localNCMDirectStatus struct {
	Available             bool                   `json:"available"`
	Requested             bool                   `json:"requested"`
	Effective             bool                   `json:"effective"`
	Busy                  bool                   `json:"busy"`
	Persistence           string                 `json:"persistence"`
	SavedEnabled          bool                   `json:"saved_enabled"`
	RequestID             string                 `json:"request_id"`
	RejectedID            string                 `json:"rejected_id,omitempty"`
	RejectedError         string                 `json:"rejected_error,omitempty"`
	Phase                 string                 `json:"phase"`
	Error                 string                 `json:"error,omitempty"`
	ModeRequested         int                    `json:"mode_requested"`
	ModeRequests          int                    `json:"mode_requests"`
	RecoveryRequired      bool                   `json:"recovery_required"`
	NetworkReady          bool                   `json:"ordinary_ipv4_network_ready"`
	OriginalModeKnown     bool                   `json:"original_mode_number_known"`
	OriginalConfiguration byte                   `json:"original_configuration"`
	OriginalProbe         []byte                 `json:"original_0x45_response,omitempty"`
	ObservationRead       string                 `json:"observation_read"`
	TargetMatched         bool                   `json:"observed_target_matched"`
	CurrentConfiguration  byte                   `json:"observed_configuration"`
	Configurations        []Configuration        `json:"observed_configurations,omitempty"`
	ConfigurationsOmitted int                    `json:"configurations_omitted"`
	Nodes                 []trustNodeState       `json:"observed_nodes,omitempty"`
	NodesOmitted          int                    `json:"nodes_omitted"`
	Binding               *directBindingEvidence `json:"binding,omitempty"`
	Network               *directNetworkEvidence `json:"network,omitempty"`
}

type localNCMDirectController struct {
	mu                           sync.Mutex
	persistence                  sync.Mutex
	state                        localNCMDirectStatus
	master, running              bool
	revision, preferenceRevision uint64
	save                         func(bool) error
	read                         func() (bool, error)
	ctx                          context.Context
	dir                          string
	sessionCancel                context.CancelFunc
	issuedContext                context.Context
	issuedRevision               uint64
	issued                       *localNCMDirectJournal
}

func newLocalNCMDirectController() *localNCMDirectController {
	return &localNCMDirectController{state: localNCMDirectStatus{Available: true, Phase: "off", Persistence: "unknown"}}
}
func (c *localNCMDirectController) snapshot() localNCMDirectStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	if s.Binding != nil {
		binding := *s.Binding
		s.Binding = &binding
	}
	if s.Network != nil {
		network := *s.Network
		s.Network = &network
	}
	s.OriginalProbe = append([]byte(nil), s.OriginalProbe...)
	s.Nodes = append([]trustNodeState(nil), s.Nodes...)
	// Descriptor projection is allocated afresh before publication and never mutated.
	s.Configurations = cloneDirectConfigurations(s.Configurations)
	return s
}
func (c *localNCMDirectController) configure(save func(bool) error, read func() (bool, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.save, c.read = save, read
}
func (c *localNCMDirectController) masterChanged(on bool) {
	c.mu.Lock()
	if c.sessionCancel != nil {
		c.sessionCancel()
		c.state.Effective = false
		c.state.NetworkReady = false
		c.state.Phase = "direct_network_stopping"
	}
	c.master = on
	c.revision++
	rev := c.revision
	c.state.Requested = false
	if on {
		c.preferenceRevision = rev
		c.state.Persistence = "loading"
		c.state.Busy = true
	}
	c.mu.Unlock()
	if on {
		go c.persist(rev, true, false)
	}
}
func (c *localNCMDirectController) set(on bool, id string) error {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdefABCDEF") != "" {
		return errors.New("DIRECT_REQUEST_INVALID")
	}
	c.mu.Lock()
	if on && !c.master {
		c.state.RejectedID = id
		c.state.RejectedError = "DIRECT_DEBUG_REQUIRED"
		c.mu.Unlock()
		return errors.New("DIRECT_DEBUG_REQUIRED")
	}
	if c.sessionCancel != nil {
		c.sessionCancel()
		c.state.Effective = false
		c.state.NetworkReady = false
		c.state.Phase = "direct_network_stopping"
	}
	c.revision++
	rev := c.revision
	c.preferenceRevision = rev
	c.state.RequestID = id
	c.state.RejectedID = ""
	c.state.RejectedError = ""
	c.state.Requested = on
	c.state.Persistence = "saving"
	c.state.Busy = true
	c.mu.Unlock()
	go c.persist(rev, false, on)
	return nil
}
func (c *localNCMDirectController) persist(rev uint64, restore, on bool) {
	c.persistence.Lock()
	defer c.persistence.Unlock()
	c.mu.Lock()
	current := c.preferenceRevision == rev
	save, read := c.save, c.read
	c.mu.Unlock()
	if !current {
		return
	}
	var err error
	if restore {
		if read == nil {
			err = errors.New("DIRECT_PREFERENCE_UNAVAILABLE")
		} else {
			on, err = read()
		}
	} else {
		if save == nil {
			err = errors.New("DIRECT_PREFERENCE_UNAVAILABLE")
		} else {
			err = save(on)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.state.SavedEnabled = on
	}
	if c.preferenceRevision != rev {
		return
	}
	c.state.Busy = c.running
	if err != nil {
		c.state.Persistence = "failed"
		c.state.Error = "DIRECT_PREFERENCE_FAILED"
		return
	}
	c.state.Persistence = "saved"
	if c.revision == rev {
		c.state.Requested = on && c.master
	}
	if !c.running && !c.state.RecoveryRequired {
		c.state.Phase = "off"
		if c.state.Requested {
			c.state.Phase = "selected_for_next_connection"
		}
		c.state.Error = ""
	}
}
func (c *localNCMDirectController) allowed(rev uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.master && c.state.Requested && c.state.Persistence == "saved" && c.revision == rev && c.ctx != nil && c.ctx.Err() == nil
}

func (c *localNCMDirectController) recoveryStatus(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hadRecovery := c.state.RecoveryRequired
	c.state.RecoveryRequired = err != nil
	if err != nil {
		c.state.Error = err.Error()
		c.state.Phase = "replug_required"
		return
	}
	if !hadRecovery || c.running || c.sessionCancel != nil {
		return
	}
	switch c.state.Phase {
	case "replug_required", "direct_network_incomplete", "direct_network_stopping", "experiment_incomplete":
		// Physical recovery resolves the old run, not a failed preference write/read.
		if c.state.Persistence == "failed" || strings.HasPrefix(c.state.Error, "DIRECT_PREFERENCE_") {
			return
		}
		c.state.Error = ""
		c.state.Phase = "recovery_verified"
	}
}
