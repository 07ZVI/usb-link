//go:build windows && amd64

package connectioninstall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RecordCoreEarlyExit leaves the reason a core returned before dispatching to
// SCM. Best effort: it overwrites the previous record and never blocks startup.
func RecordCoreEarlyExit(version, stage string, cause error) {
	state, e := StateDirectory()
	if e != nil {
		return
	}
	_ = writeInstallationJSON(filepath.Join(state, CoreEarlyExitName), newCoreEarlyExit(version, uint32(os.Getpid()), time.Now(), stage, cause))
}

// ClearCoreEarlyExit runs once the SCM dispatcher hosts this core, so a stale
// record is never blamed for a later failure.
func ClearCoreEarlyExit() {
	if state, e := StateDirectory(); e == nil {
		_ = os.Remove(filepath.Join(state, CoreEarlyExitName))
	}
}

func readCoreEarlyExit() *CoreEarlyExit {
	state, e := StateDirectory()
	if e != nil {
		return nil
	}
	b, e := coreProtectedRead(filepath.Join(state, CoreEarlyExitName), false, true)
	var r CoreEarlyExit
	if e != nil || json.Unmarshal(b, &r) != nil {
		return nil
	}
	return &r
}

// startEvidence adds the SCM status and this attempt's early-exit record.
func startEvidence(err error, version string, began time.Time) error {
	if err == nil {
		return nil
	}
	exit, _ := coreServiceExitStatus()
	return withStartEvidence(err, exit, readCoreEarlyExit(), version, began)
}
