package connectioninstall

import (
	"os"
	"strings"
	"testing"
)

func TestDesktopCandidatesAreIndependentAndDefaultOff(t *testing.T) {
	t.Setenv("SUHANG_DESKTOP_STREAMING", "")
	t.Setenv("SUHANG_DESKTOP_BOUNDED_IPC", "")
	defer setDesktopRuntimeExperiment("CDEFAULT", 0)
	if DesktopStreamingEnabled() {
		t.Fatal("streaming default enabled")
	}
	id := strings.Repeat("e", 32)
	for _, kind := range []string{"CSTREAMING", "CIPC"} {
		if validMeasurement(kind, 900, id) != nil || validMeasurement(kind, 899, id) == nil || validMeasurement(kind, 901, id) == nil {
			t.Fatal(kind)
		}
		if _, e := setDesktopRuntimeExperiment(kind, 900); e != nil {
			t.Fatal(e)
		}
		if DesktopStreamingEnabled() != (kind == "CSTREAMING") || (os.Getenv("SUHANG_DESKTOP_BOUNDED_IPC") == "1") != (kind == "CIPC") {
			t.Fatal("multiple C candidates enabled", kind)
		}
	}
	if _, e := setDesktopRuntimeExperiment("CDEFAULT", 0); e != nil {
		t.Fatal(e)
	}
	if DesktopStreamingEnabled() || os.Getenv("SUHANG_DESKTOP_BOUNDED_IPC") == "1" {
		t.Fatal("experiment not restored")
	}
}
