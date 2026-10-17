package ipadncm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const localAMDSHoldJournalFile = "local-amds-hold-v1.json"
const localAMDSHoldJournalLimit = 4096
const localAMDSHoldService = "Apple Mobile Device Service"

type localAMDSHoldJournal struct {
	Schema        int    `json:"schema"`
	Service       string `json:"service"`
	OriginalState uint32 `json:"original_state"`
	StartType     uint32 `json:"start_type"`
	ConfigHash    string `json:"config_hash"`
	Restored      bool   `json:"restored"`
}

func (j localAMDSHoldJournal) valid() bool {
	return j.Schema == 1 && j.Service == localAMDSHoldService && (j.OriginalState == 1 || j.OriginalState == 4) && j.StartType >= 2 && j.StartType <= 4 && len(j.ConfigHash) == 64 && strings.Trim(j.ConfigHash, "0123456789abcdef") == ""
}
func decodeLocalAMDSHoldJournal(b []byte) (localAMDSHoldJournal, error) {
	var j localAMDSHoldJournal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > localAMDSHoldJournalLimit || d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
		return j, errors.New("AMDS_HOLD_JOURNAL_INVALID")
	}
	return j, nil
}

type localAMDSHoldFailure struct {
	Code     string
	Native   uint32
	Identity *localAMDSHoldIdentity
}

func (e *localAMDSHoldFailure) Error() string { return e.Code }
func amdsHoldError(code string, native uint32) error {
	return &localAMDSHoldFailure{Code: code, Native: native}
}

type localAMDSHoldSample struct {
	Identity      *localAMDSHoldIdentity `json:"identity,omitempty"`
	OriginalState uint32                 `json:"original_state"`
	ServiceState  uint32                 `json:"service_state"`
	StartType     uint32                 `json:"start_type"`
	Restored      bool                   `json:"restored"`
}
type localAMDSHoldStatus struct {
	Available     bool   `json:"available"`
	Requested     bool   `json:"requested"`
	Effective     bool   `json:"effective"`
	Busy          bool   `json:"busy"`
	Persistence   string `json:"persistence"`
	SavedEnabled  bool   `json:"saved_enabled"`
	RequestID     string `json:"request_id,omitempty"`
	RejectedID    string `json:"rejected_id,omitempty"`
	RejectedError string `json:"rejected_error,omitempty"`
	Phase         string `json:"phase"`
	Error         string `json:"error,omitempty"`
	CauseCode     string `json:"cause_code,omitempty"`
	NativeCode    uint32 `json:"native_code,omitempty"`
	SampledUTC    string `json:"sampled_utc,omitempty"`
	RunID         string `json:"run_id,omitempty"`
	SampledMS     int64  `json:"sampled_ms"`
	localAMDSHoldSample
}

type localAMDSHoldObservation struct {
	State, StartType uint32
	ConfigHash       string
}

func localAMDSHoldTransition(j localAMDSHoldJournal, wanted uint32, read func() (localAMDSHoldObservation, error), change func(uint32) error, allowed func() bool) (localAMDSHoldObservation, error) {
	var none localAMDSHoldObservation
	if !j.valid() || (wanted != 1 && wanted != j.OriginalState) {
		return none, amdsHoldError("AMDS_HOLD_JOURNAL_INVALID", 0)
	}
	before, e := read()
	if e != nil {
		return none, e
	}
	if before.ConfigHash != j.ConfigHash || before.StartType != j.StartType {
		return before, amdsHoldError("AMDS_HOLD_CONFIG_CHANGED", 0)
	}
	if before.State != 1 && before.State != 4 {
		return before, amdsHoldError("AMDS_HOLD_TRANSITION_PENDING", 0)
	}
	if allowed != nil && !allowed() {
		return before, amdsHoldError("AMDS_HOLD_REQUEST_CANCELLED", 0)
	}
	if before.State != wanted {
		if e = change(wanted); e != nil {
			return before, e
		}
	}
	after, e := read()
	if e != nil {
		return before, e
	}
	if after.ConfigHash != j.ConfigHash || after.StartType != j.StartType {
		return after, amdsHoldError("AMDS_HOLD_CONFIG_CHANGED", 0)
	}
	if after.State != wanted {
		return after, amdsHoldError("AMDS_HOLD_STATE_UNCONFIRMED", 0)
	}
	return after, nil
}
