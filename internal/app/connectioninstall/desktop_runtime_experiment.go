package connectioninstall

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var desktopRuntimeExperiment struct {
	sync.Mutex
	generation uint64
	timer      *time.Timer
	until      time.Time
}

// The authenticated integrator can enable exactly one bounded C candidate.
// No system environment or persistent policy is modified. IPC applies only
// to the next renderer launch; streaming applies to the next preparation.
func setDesktopRuntimeExperiment(kind string, seconds int) (any, error) {
	desktopRuntimeExperiment.Lock()
	defer desktopRuntimeExperiment.Unlock()
	if (kind != "CSTREAMING" && kind != "CIPC" && kind != "CDEFAULT") || (kind == "CDEFAULT" && seconds != 0) || (kind != "CDEFAULT" && seconds != 900) {
		return nil, fmt.Errorf("invalid fixed desktop experiment")
	}
	if desktopRuntimeExperiment.timer != nil {
		desktopRuntimeExperiment.timer.Stop()
	}
	desktopRuntimeExperiment.generation++
	g := desktopRuntimeExperiment.generation
	for _, name := range []string{"SUHANG_DESKTOP_STREAMING", "SUHANG_DESKTOP_BOUNDED_IPC"} {
		if e := os.Unsetenv(name); e != nil {
			return nil, e
		}
	}
	desktopRuntimeExperiment.until = time.Time{}
	if kind != "CDEFAULT" {
		name := "SUHANG_DESKTOP_STREAMING"
		if kind == "CIPC" {
			name = "SUHANG_DESKTOP_BOUNDED_IPC"
		}
		if e := os.Setenv(name, "1"); e != nil {
			return nil, e
		}
		desktopRuntimeExperiment.until = time.Now().Add(900 * time.Second)
		desktopRuntimeExperiment.timer = time.AfterFunc(900*time.Second, func() {
			desktopRuntimeExperiment.Lock()
			defer desktopRuntimeExperiment.Unlock()
			if desktopRuntimeExperiment.generation == g {
				os.Unsetenv(name)
				desktopRuntimeExperiment.until = time.Time{}
			}
		})
	}
	return map[string]any{"streaming": DesktopStreamingEnabled(), "bounded_ipc_next_launch": os.Getenv("SUHANG_DESKTOP_BOUNDED_IPC") == "1", "expires_utc": desktopRuntimeExperiment.until, "startup_peak_not_measured_by_runtime_toggle": true}, nil
}
