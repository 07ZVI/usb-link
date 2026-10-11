// Package grouptrial manages a temporary, consented grouping experiment. All
// saved transactions require restoration, including partial Apply failures.
package grouptrial

type Backend interface {
	Eligible() string
	Save() string
	Apply() string
	Restart() string
	Activate() string
	Observe() string
	Restore() string
	Clear() string
}

type Report struct {
	Status                string `json:"status"`
	Error                 string `json:"error,omitempty"`
	Consent               bool   `json:"consent"`
	BackupSaved           bool   `json:"backup_saved"`
	WriteAttempted        bool   `json:"write_attempted"`
	RestartAttempted      bool   `json:"restart_attempted"`
	ActivationAttempted   bool   `json:"mode_reactivation_attempted"`
	Observation           string `json:"observation,omitempty"`
	RestoreAttempted      bool   `json:"restore_attempted"`
	RestoreCompleted      bool   `json:"restore_completed"`
	RestoreError          string `json:"restore_error,omitempty"`
	JournalCleared        bool   `json:"journal_cleared"`
	ConfigurationRetained bool   `json:"configuration_retained,omitempty"`
}

func Run(b Backend, consent func() bool) (r Report) {
	return run(b, consent, nil)
}

// A durable grouping has the same eligibility, backup and rollback gates as a
// trial. Only a successful observation and durable commit can skip rollback.
// The commit callback owns readback and durable recovery-receipt preservation.
func RunPersistent(b Backend, consent func() bool, commit func() string) Report {
	return run(b, consent, commit)
}

func run(b Backend, consent func() bool, commit func() string) (r Report) {
	r.Status = "NOT_ELIGIBLE_NO_CHANGE"
	if r.Error = b.Eligible(); r.Error != "" {
		return
	}
	r.Consent = consent()
	if !r.Consent {
		r.Status = "DECLINED_NO_CHANGE"
		return
	}
	// The consent dialog can remain open; recheck before saving or writing.
	if r.Error = b.Eligible(); r.Error != "" {
		return
	}
	r.Status = "BACKUP_FAILED_NO_CHANGE"
	if r.Error = b.Save(); r.Error != "" {
		return
	}
	r.BackupSaved = true
	defer func() {
		if r.ConfigurationRetained {
			return
		}
		r.RestoreAttempted = true
		if r.RestoreError = b.Restore(); r.RestoreError != "" {
			r.Status = "RESTORE_PENDING_STOP"
			return
		}
		r.RestoreCompleted = true
		if r.RestoreError = b.Clear(); r.RestoreError != "" {
			r.Status = "RECOVERY_JOURNAL_PENDING_STOP"
			return
		}
		r.JournalCleared = true
	}()
	r.WriteAttempted = true
	r.Status = "APPLY_FAILED_RESTORING"
	if r.Error = b.Apply(); r.Error != "" {
		return
	}
	r.RestartAttempted = true
	r.Status = "RESTART_FAILED_RESTORING"
	if r.Error = b.Restart(); r.Error != "" {
		return
	}
	r.ActivationAttempted = true
	r.Status = "MODE_REACTIVATION_FAILED_RESTORING"
	if r.Error = b.Activate(); r.Error != "" {
		return
	}
	r.Observation = b.Observe()
	if commit != nil {
		if r.Error = commit(); r.Error != "" {
			r.Status = "COMMIT_FAILED_RESTORING"
			return
		}
		r.ConfigurationRetained = true
		r.Status = "CONFIGURATION_RETAINED_WITH_RECOVERY_RECEIPT"
		return
	}
	r.Status = "TRIAL_COMPLETE_RESTORED"
	return
}
