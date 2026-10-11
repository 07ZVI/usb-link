package ipadncm

// The owner serializes admission. State changes below are pure so cancellation
// and failure do not accidentally turn an unverified restoration into success.
type softwareReconnectControlState struct {
	available, pending, running, recovering, blocked bool
	phase, problem                                   string
	softwareAttempts                                 uint64
}

func (s *softwareReconnectControlState) busy() bool       { return s.pending || s.running || s.recovering }
func (s *softwareReconnectControlState) canConnect() bool { return !s.busy() && !s.blocked }
func (s *softwareReconnectControlState) queue() bool {
	if !s.available || s.busy() || s.blocked {
		return false
	}
	s.pending, s.phase, s.problem = true, "awaiting_verified_ipad_cleanup", ""
	return true
}
func (s *softwareReconnectControlState) begin() bool {
	if !s.pending || s.running || s.recovering {
		return false
	}
	s.pending, s.running, s.phase = false, true, "checking_exact_current_root"
	return true
}
func (s *softwareReconnectControlState) finish(r softwareReconnectDraftResult, problem string, canceled, receiptUnresolved bool) {
	s.pending, s.running = false, false
	if r.SoftwareAttempt {
		s.softwareAttempts++
	}
	s.blocked = r.RecoveryPending || receiptUnresolved
	s.problem = problem
	switch {
	case s.blocked:
		s.phase = "recovery_required_receipt_retained"
	case canceled:
		s.phase = "canceled_no_unverified_root_changes"
	case problem != "":
		s.phase = "failed_no_unverified_root_changes"
	case r.DisabledVerified && r.RestoredVerified:
		s.phase = "cm_root_restored_network_not_yet_verified"
	default:
		s.phase = "no_root_change"
	}
}

func (s *softwareReconnectControlState) queueSetting(enabled bool) bool {
	if s.busy() || enabled && s.blocked {
		return false
	}
	s.pending, s.phase, s.problem = true, "awaiting_verified_ipad_cleanup", ""
	return true
}

func (s *softwareReconnectControlState) withdrawIdleForUpgrade() bool {
	if s.running || s.recovering {
		return false
	}
	if s.pending {
		s.pending = false
		s.phase = "idle_request_withdrawn_for_upgrade"
	}
	return true
}
