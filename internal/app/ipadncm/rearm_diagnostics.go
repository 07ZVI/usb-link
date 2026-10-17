package ipadncm

import "time"

// Diagnostic projection of the existing gates, never an admission predicate.
// Root identity is compared privately and only the relationship is retained.
type rearmDiagnosticSample struct {
	Attempt          uint64 `json:"software_attempt"`
	WaitedMS         int64  `json:"waited_ms"`
	Readable         bool   `json:"presence_readable"`
	Absent           bool   `json:"no_mobile_root"`
	Candidate        bool   `json:"unique_candidate"`
	SameRoot         bool   `json:"same_previous_root"`
	PreviousKnown    bool   `json:"previous_root_known"`
	Completed        bool   `json:"previous_application_ran"`
	AbsenceObserved  bool   `json:"rearm_absence_observed"`
	AbsenceConfirmed bool   `json:"sustained_cached_absence_confirmed"`
	FastReplug       bool   `json:"same_root_ready_after_cached_absence"`
	SameRootSinceMS  int64  `json:"same_root_since_wait_ms"`
	SameRootWaitedMS int64  `json:"same_root_waited_ms"`
	MinimumMS        int64  `json:"same_root_minimum_ms"`
	Reason           string `json:"reason"`
}

func rearmDiagnostic(now, start time.Time, previous string, p idlePresence, completed bool, g idleReattachGate, detached, newReady, sameReady bool) rearmDiagnosticSample {
	s := rearmDiagnosticSample{WaitedMS: max(0, now.Sub(start).Milliseconds()), Readable: p.readable, Absent: p.absent, Candidate: p.candidate, SameRoot: previous != "" && p.identity == previous, PreviousKnown: previous != "", Completed: completed, AbsenceObserved: g.absent, SameRootSinceMS: -1, MinimumMS: 2000}
	s.AbsenceConfirmed = g.fastReplug
	s.FastReplug = sameReady && completed && g.fastReplug
	if s.FastReplug {
		s.MinimumMS = 0
	}
	if !g.stable.since.IsZero() {
		s.SameRootSinceMS = g.stable.since.Sub(start).Milliseconds()
		s.SameRootWaitedMS = max(0, now.Sub(g.stable.since).Milliseconds())
	}
	switch {
	case detached:
		s.Reason = "stable_absence_ready"
	case newReady:
		s.Reason = "different_root_ready"
	case s.FastReplug:
		s.Reason = "same_root_ready_after_cached_absence"
	case sameReady:
		s.Reason = "same_root_ready"
	case !p.readable:
		s.Reason = "presence_unreadable"
	case p.absent:
		s.Reason = "waiting_after_absence"
	case !p.candidate:
		s.Reason = "no_unique_candidate"
	case previous == "":
		s.Reason = "previous_root_unknown"
	case !s.SameRoot:
		s.Reason = "different_root_stabilizing"
	case !completed && !g.absent:
		s.Reason = "failed_session_requires_observed_absence"
	default:
		s.Reason = "same_root_stabilizing"
	}
	return s
}

// Periodic identical waiting samples need no event. A new/reset stability
// interval, changed refusal or ready transition is always retained.
func sameRearmDiagnosticState(a, b rearmDiagnosticSample) bool {
	a.WaitedMS, b.WaitedMS, a.SameRootWaitedMS, b.SameRootWaitedMS = 0, 0, 0, 0
	return a == b
}
