package connectioninstall

import (
	"fmt"
	"strings"
	"time"
)

const CoreEarlyExitName = "core-early-exit.json"
const coreEarlyExitSlack = time.Minute

// CoreEarlyExit is the durable record of a core that returned before the SCM
// dispatcher took over, which SCM can only report as a start timeout (1053).
type CoreEarlyExit struct {
	Version string `json:"version"`
	PID     uint32 `json:"pid"`
	UTC     string `json:"utc"`
	Stage   string `json:"stage"`
	Error   string `json:"error"`
}

func boundedEarlyText(s string, n int) string {
	out := make([]byte, 0, min(len(s), n))
	for _, r := range s {
		if len(out) >= n {
			break
		}
		if r >= 0x20 && r < 0x7f {
			out = append(out, byte(r))
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

func newCoreEarlyExit(version string, pid uint32, now time.Time, stage string, err error) CoreEarlyExit {
	r := CoreEarlyExit{Version: boundedEarlyText(version, 32), PID: pid, UTC: now.UTC().Format(time.RFC3339Nano), Stage: boundedEarlyText(stage, 64)}
	if err != nil {
		r.Error = boundedEarlyText(err.Error(), 400)
	}
	return r
}

// matchCoreEarlyExit ties a record to the attempt being diagnosed: the version
// being started and a time no earlier than a minute before the attempt began.
func matchCoreEarlyExit(r CoreEarlyExit, version string, began time.Time) bool {
	at, err := time.Parse(time.RFC3339Nano, r.UTC)
	return err == nil && r.Version == version && !at.Before(began.Add(-coreEarlyExitSlack))
}

func formatCoreEarlyExit(r CoreEarlyExit) string {
	return fmt.Sprintf("core_early_exit stage=%s error=%s pid=%d utc=%s", r.Stage, r.Error, r.PID, r.UTC)
}

func formatCoreServiceExit(e *coreServiceExit) string {
	if e == nil {
		return "scm_status=unknown"
	}
	return fmt.Sprintf("scm_state=%d win32=%d exit=%d", e.State, e.Win32, e.Specific)
}

// withStartEvidence appends the SCM status and, when it belongs to this
// attempt, the core's own early-exit record. The cause stays in the %w chain.
func withStartEvidence(err error, exit *coreServiceExit, early *CoreEarlyExit, version string, began time.Time) error {
	if err == nil {
		return nil
	}
	parts := []string{formatCoreServiceExit(exit)}
	if early != nil && matchCoreEarlyExit(*early, version, began) {
		parts = append(parts, formatCoreEarlyExit(*early))
	}
	return fmt.Errorf("%w; %s", err, strings.Join(parts, " "))
}
