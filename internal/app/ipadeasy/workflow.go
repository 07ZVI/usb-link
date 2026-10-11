// Package ipadeasy sequences the single-launcher preparation, mode and native
// start checks. Completing diagnostics is not successful networking.
package ipadeasy

type ModeOutcome struct {
	Ready          bool
	PauseAttempted bool
	Restored       bool
	Error          string
}
type Report struct {
	Stage           string `json:"stage"`
	Error           string `json:"error,omitempty"`
	ModeCheckRun    bool   `json:"mode_check_run"`
	StartupCheckRun bool   `json:"startup_check_run"`
}

func Run(prepare func() string, mode func() ModeOutcome, startup func()) Report {
	r := Report{Stage: "PREPARE"}
	if r.Error = prepare(); r.Error != "" {
		return r
	}
	r.Stage = "MODE_CHECK"
	r.ModeCheckRun = true
	m := mode()
	// A mode receipt is insufficient if an owned pause wasn't restored.
	if m.PauseAttempted && !m.Restored {
		r.Error = "APPLE_SERVICE_RESTORE_NOT_CONFIRMED"
		return r
	}
	if m.Error != "" {
		r.Error = m.Error
		return r
	}
	if !m.Ready {
		r.Error = "NCM_NOT_ACTIVE_AFTER_MODE_CHECK"
		return r
	}
	r.Stage = "NATIVE_START_CHECK"
	r.StartupCheckRun = true
	startup()
	r.Stage = "DIAGNOSTICS_COMPLETE"
	return r
}
