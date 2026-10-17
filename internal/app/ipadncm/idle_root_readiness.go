package ipadncm

// Root readiness only postpones authorization while Windows starts a candidate.
// It is not evidence of USB identity, consent or network readiness.
type idleRootObservation struct {
	ContextActive bool
	ExactRoot     bool
	StateReadable bool
	Status        uint32
	Problem       uint32
}

func idleRootReadiness(expected string, before, after idlePresence, o idleRootObservation) string {
	if !o.ContextActive {
		return "context_cancelled"
	}
	if expected == "" || !before.readable || !after.readable {
		return "root_inventory_unreadable"
	}
	if !before.candidate || !after.candidate || before.identity != expected || after.identity != expected || !o.ExactRoot {
		return "root_changed_or_not_unique"
	}
	if !o.StateReadable {
		return "root_status_unreadable"
	}
	if o.Status&0x100 != 0 {
		return "root_restart_required"
	}
	if o.Problem != 0 || o.Status&0x400 != 0 { // DN_HAS_PROBLEM
		return "root_problem_present"
	}
	if o.Status&8 == 0 {
		return "root_not_started"
	}
	return "root_started_not_authorization"
}
