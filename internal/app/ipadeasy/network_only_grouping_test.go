package ipadeasy

import (
	"reflect"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"testing"
)

type groupingIsolationBackend struct {
	calls                        []string
	active                       bool
	mode                         ModeOutcome
	isolationError, restoreError string
}

func (b *groupingIsolationBackend) step(name string) string {
	b.calls = append(b.calls, name)
	return ""
}
func (b *groupingIsolationBackend) Eligible() string { return b.step("eligible") }
func (b *groupingIsolationBackend) Save() string     { return b.step("save") }
func (b *groupingIsolationBackend) Apply() string    { return b.step("apply") }
func (b *groupingIsolationBackend) Restart() string  { return b.step("restart") }
func (b *groupingIsolationBackend) Activate() string {
	b.step("mode")
	return CompleteGroupingModeWithNetworkOnly(b.active, b.mode, func() string {
		b.step("fresh_admission_and_isolation")
		return b.isolationError
	})
}
func (b *groupingIsolationBackend) Observe() string { return b.step("network_start") }
func (b *groupingIsolationBackend) Restore() string {
	b.step("restore")
	return b.restoreError
}
func (b *groupingIsolationBackend) Clear() string { return b.step("clear") }

func TestGroupingFallbackIsolationFailureReturnsThroughSavedTransactionRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, isolation, restore string
	}{
		{"fresh root or policy mismatch", "SAME_ROOT_PROOF_CHANGED", ""},
		{"native node isolation failed", "NETWORK_ONLY_SETUP_FAILED", ""},
		{"group recovery also failed", "NETWORK_ONLY_SETUP_FAILED", "RESTORE_FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &groupingIsolationBackend{active: true, mode: ModeOutcome{Ready: true}, isolationError: tc.isolation, restoreError: tc.restore}
			r := grouptrial.RunPersistent(b, func() bool { return true }, func() string {
				t.Fatal("failed post-mode isolation reached durable grouping commit")
				return ""
			})
			want := []string{"eligible", "eligible", "save", "apply", "restart", "mode", "fresh_admission_and_isolation", "restore"}
			if tc.restore == "" {
				want = append(want, "clear")
			}
			if !reflect.DeepEqual(b.calls, want) || r.Error != tc.isolation || !r.BackupSaved || !r.ActivationAttempted || !r.RestoreAttempted || r.ConfigurationRetained || r.Observation != "" {
				t.Fatal("isolation failure bypassed saved recovery or started networking", r, b.calls)
			}
			if tc.restore == "" {
				if !r.RestoreCompleted || !r.JournalCleared {
					t.Fatal("verified rollback was skipped", r)
				}
			} else if r.RestoreCompleted || r.JournalCleared || r.RestoreError != tc.restore || r.Status != "RESTORE_PENDING_STOP" {
				t.Fatal("failed rollback lost its recovery obligation", r)
			}
		})
	}
}

func TestGroupingFallbackDoesNotIsolateFailedModeOrUnrestoredService(t *testing.T) {
	for _, tc := range []struct {
		mode ModeOutcome
		want string
	}{
		{ModeOutcome{Ready: true, PauseAttempted: true, Error: "MODE_ERROR"}, "GROUPING_MODE_APPLE_SERVICE_RESTORE_UNCONFIRMED"},
		{ModeOutcome{Error: "MODE_ERROR"}, "MODE_ERROR"},
		{ModeOutcome{}, "GROUPING_MODE_NCM_UNCONFIRMED"},
	} {
		for _, active := range []bool{false, true} {
			b := &groupingIsolationBackend{active: active, mode: tc.mode}
			r := grouptrial.Run(b, func() bool { return true })
			wantCalls := []string{"eligible", "eligible", "save", "apply", "restart", "mode", "restore", "clear"}
			if r.Error != tc.want || !r.RestoreCompleted || !r.JournalCleared || !reflect.DeepEqual(b.calls, wantCalls) {
				t.Fatal("failed mode changed node or recovery semantics", active, r, b.calls)
			}
		}
	}
}

func TestGroupingFallbackSuccessIsolatesOnlyActiveI7BeforeNetworking(t *testing.T) {
	for _, active := range []bool{false, true} {
		b := &groupingIsolationBackend{active: active, mode: ModeOutcome{Ready: true, PauseAttempted: true, Restored: true}}
		r := grouptrial.RunPersistent(b, func() bool { return true }, func() string { return b.step("commit") })
		want := []string{"eligible", "eligible", "save", "apply", "restart", "mode"}
		if active {
			want = append(want, "fresh_admission_and_isolation")
		}
		want = append(want, "network_start", "commit")
		if r.Error != "" || !r.ConfigurationRetained || r.RestoreAttempted || !reflect.DeepEqual(b.calls, want) {
			t.Fatal("successful fallback changed normal mode or isolation order", active, r, b.calls)
		}
	}
}
