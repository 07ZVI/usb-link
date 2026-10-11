package grouptrial

import (
	"context"
	"time"
)

// Evidence contains no instance identifiers. Missing enumeration is temporary;
// an observed different or ambiguous device is never treated as a retry.
type ReadinessEvidence struct {
	QueryFailed, QueryIncomplete       bool
	Devices, Roots                     int
	PhysicalMatches, RootMatches       bool
	RootStateReadable, RootProblemFree bool
	NeedsReboot                        bool
}

func ReactivationReadiness(e ReadinessEvidence) string {
	if e.QueryFailed {
		return "REACTIVATION_ENUMERATION_FAILED"
	}
	if e.Devices > 1 || e.Roots > 1 {
		return "REACTIVATION_TARGET_AMBIGUOUS"
	}
	if e.Devices == 1 && !e.PhysicalMatches || e.Roots == 1 && !e.RootMatches {
		return "ROOT_CHANGED_BEFORE_MODE_REACTIVATION"
	}
	if e.QueryIncomplete {
		return "REACTIVATION_ENUMERATION_INCOMPLETE"
	}
	if e.NeedsReboot {
		return "TARGET_WINDOWS_RESTART_REQUIRED"
	}
	if e.Devices == 0 || e.Roots == 0 || !e.RootStateReadable || !e.RootProblemFree {
		return "WAITING_FOR_EXACT_ROOT"
	}
	return "READY"
}

type ReadinessSample struct {
	ElapsedMS int64  `json:"elapsed_ms"`
	Status    string `json:"status"`
}

// Callers supply an overall deadline and a context-aware read. Cancellation
// and timeout stop before activation; the transaction still restores its state.
func WaitReactivation(ctx context.Context, interval time.Duration, read func(context.Context) ReadinessEvidence) ([]ReadinessSample, string) {
	started := time.Now()
	var samples []ReadinessSample
	if interval <= 0 {
		return samples, "REACTIVATION_WAIT_INTERVAL_INVALID"
	}
	for {
		if ctx.Err() != nil {
			return samples, readinessContextError(ctx)
		}
		evidence := read(ctx)
		if ctx.Err() != nil {
			return samples, readinessContextError(ctx)
		}
		status := ReactivationReadiness(evidence)
		samples = append(samples, ReadinessSample{time.Since(started).Milliseconds(), status})
		if status == "READY" {
			return samples, ""
		}
		if status != "WAITING_FOR_EXACT_ROOT" {
			return samples, status
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return samples, readinessContextError(ctx)
		case <-timer.C:
		}
	}
}

func readinessContextError(ctx context.Context) string {
	if ctx.Err() == context.DeadlineExceeded {
		return "EXACT_ROOT_REENUMERATION_TIMEOUT"
	}
	return "MODE_REACTIVATION_CANCELLED"
}
