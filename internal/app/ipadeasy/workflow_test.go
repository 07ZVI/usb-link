package ipadeasy

import (
	"reflect"
	"testing"
)

func TestSingleLauncherOrderAndStopBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, prepareError string
		mode               ModeOutcome
		want               []string
		wantError          string
	}{
		{"already active", "", ModeOutcome{Ready: true}, []string{"prepare", "mode", "startup"}, ""},
		{"switch and restored", "", ModeOutcome{Ready: true, PauseAttempted: true, Restored: true}, []string{"prepare", "mode", "startup"}, ""},
		{"installation declined", "INSTALL_DECLINED", ModeOutcome{}, []string{"prepare"}, "INSTALL_DECLINED"},
		{"reboot required", "REBOOT_REQUIRED_BEFORE_RETEST", ModeOutcome{}, []string{"prepare"}, "REBOOT_REQUIRED_BEFORE_RETEST"},
		{"mode consent declined", "", ModeOutcome{Error: "MODE_CHANGE_DECLINED"}, []string{"prepare", "mode"}, "MODE_CHANGE_DECLINED"},
		{"mode ack without active NCM", "", ModeOutcome{PauseAttempted: true, Restored: true}, []string{"prepare", "mode"}, "NCM_NOT_ACTIVE_AFTER_MODE_CHECK"},
		{"restoration failure despite NCM", "", ModeOutcome{Ready: true, PauseAttempted: true}, []string{"prepare", "mode"}, "APPLE_SERVICE_RESTORE_NOT_CONFIRMED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			r := Run(func() string { events = append(events, "prepare"); return tc.prepareError }, func() ModeOutcome { events = append(events, "mode"); return tc.mode }, func() { events = append(events, "startup") })
			if !reflect.DeepEqual(events, tc.want) || r.Error != tc.wantError {
				t.Fatalf("events=%v report=%+v", events, r)
			}
			if r.StartupCheckRun != (len(events) == 3) {
				t.Fatal("startup report differs from actual invocation")
			}
		})
	}
}
