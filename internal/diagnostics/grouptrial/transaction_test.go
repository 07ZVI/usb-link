package grouptrial

import (
	"reflect"
	"testing"
)

type fake struct {
	calls            []string
	fail             string
	eligibilityCalls int
}

func (f *fake) step(s string) string {
	f.calls = append(f.calls, s)
	if f.fail == s {
		return "FAILED"
	}
	return ""
}
func (f *fake) Eligible() string {
	f.eligibilityCalls++
	if f.fail == "changed" && f.eligibilityCalls == 2 {
		f.calls = append(f.calls, "eligible")
		return "TARGET_CHANGED"
	}
	return f.step("eligible")
}
func (f *fake) Save() string     { return f.step("save") }
func (f *fake) Apply() string    { return f.step("apply") }
func (f *fake) Restart() string  { return f.step("restart") }
func (f *fake) Activate() string { return f.step("activate") }
func (f *fake) Observe() string  { f.step("observe"); return "NATIVE_DRIVER_RESULT" }
func (f *fake) Restore() string  { return f.step("restore") }
func (f *fake) Clear() string    { return f.step("clear") }
func TestTransactionRestoresEverySavedTrial(t *testing.T) {
	for _, tc := range []struct {
		fail     string
		consent  bool
		calls    []string
		restored bool
	}{
		{"", true, []string{"eligible", "eligible", "save", "apply", "restart", "activate", "observe", "restore", "clear"}, true},
		{"eligible", true, []string{"eligible"}, false},
		{"", false, []string{"eligible"}, false},
		{"changed", true, []string{"eligible", "eligible"}, false},
		{"save", true, []string{"eligible", "eligible", "save"}, false},
		{"apply", true, []string{"eligible", "eligible", "save", "apply", "restore", "clear"}, true},
		{"restart", true, []string{"eligible", "eligible", "save", "apply", "restart", "restore", "clear"}, true},
		{"activate", true, []string{"eligible", "eligible", "save", "apply", "restart", "activate", "restore", "clear"}, true},
		{"restore", true, []string{"eligible", "eligible", "save", "apply", "restart", "activate", "observe", "restore"}, false},
		{"clear", true, []string{"eligible", "eligible", "save", "apply", "restart", "activate", "observe", "restore", "clear"}, true},
	} {
		f := &fake{fail: tc.fail}
		r := Run(f, func() bool { return tc.consent })
		if !reflect.DeepEqual(f.calls, tc.calls) || r.RestoreCompleted != tc.restored {
			t.Fatalf("%+v: %+v calls=%v", tc, r, f.calls)
		}
		if tc.fail == "restore" && r.JournalCleared {
			t.Fatal("failed restore lost recovery journal")
		}
	}
}
func TestPanicStillRestores(t *testing.T) {
	f := &panicking{fake: fake{}}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("missing panic")
			}
		}()
		Run(f, func() bool { return true })
	}()
	if got := f.calls[len(f.calls)-2:]; !reflect.DeepEqual(got, []string{"restore", "clear"}) {
		t.Fatal(f.calls)
	}
}

type panicking struct{ fake }

func (*panicking) Observe() string { panic("observation failure") }

func TestPersistentConfigurationRetainsOnlyAfterDurableCommit(t *testing.T) {
	for _, fail := range []string{"", "apply", "commit"} {
		f := &fake{fail: fail}
		committed := false
		r := RunPersistent(f, func() bool { return true }, func() string {
			committed = true
			if fail == "commit" {
				return "DURABLE_RECEIPT_FAILED"
			}
			return ""
		})
		if fail == "" {
			if !committed || !r.ConfigurationRetained || r.RestoreAttempted || r.JournalCleared {
				t.Fatal("configuration receipt lost", r, f.calls)
			}
		} else {
			if r.ConfigurationRetained || !r.RestoreCompleted || !r.JournalCleared {
				t.Fatal("failed persistent apply did not roll back", r, f.calls)
			}
			if fail == "apply" && committed {
				t.Fatal("commit invoked after failed apply")
			}
		}
	}
}
