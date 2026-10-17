//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func restartFixture() localRestartJob {
	return localRestartJob{Schema: 1, ID: strings.Repeat("a", 32), Binding: CoreServiceBinding{Version: 1, Product: ProductID, OwnerSID: "S-1-5-21-1-2-3-1001", Executable: `C:\Program Files\USB Link\App\USB Link.exe`, SHA256: strings.Repeat("b", 64)}, Session: 1, CorePID: 7, CoreCreation: 10, Consent: localRestartConsent{Revision: 1, TokenHash: strings.Repeat("c", 64)}, Phase: "prepared"}
}
func TestLocalRestartReceiptIdentityAndCompletion(t *testing.T) {
	j := restartFixture()
	b, _ := json.Marshal(j)
	got, e := decodeRestartJob(b)
	if e != nil || got != j {
		t.Fatalf("roundtrip: %v", e)
	}
	cases := map[string]func(*localRestartJob){"foreign_product": func(j *localRestartJob) { j.Binding.Product = "other" }, "schema": func(j *localRestartJob) { j.Binding.Version = 2 }, "helper_half": func(j *localRestartJob) { j.Phase = "failed"; j.Error = "LOCAL_RESTART_HELPER_FAILED"; j.HelperPID = 8 }, "ack_not_complete": func(j *localRestartJob) {
		j.Phase = "completed"
		j.HelperPID = 8
		j.HelperCreation = 11
		j.Admitted = true
	}, "arbitrary_error": func(j *localRestartJob) { j.Phase = "failed"; j.Error = `C:\private\token` }, "prepared_consumed": func(j *localRestartJob) { j.Admitted = true }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			x := j
			change(&x)
			b, _ := json.Marshal(x)
			if _, e := decodeRestartJob(b); e == nil {
				t.Fatal("accepted invalid receipt")
			}
		})
	}
	duplicated := strings.Replace(string(b), `"schema":1`, `"schema":1,"schema":1`, 1)
	if _, e := decodeRestartJob([]byte(duplicated)); e == nil {
		t.Fatal("duplicate field accepted")
	}
	x := j
	x.Phase = "completed"
	x.HelperPID = 8
	x.HelperCreation = 11
	x.Admitted = true
	x.TaskSHA = strings.Repeat("d", 64)
	x.CoreReadable = true
	x.LoginRequested = true
	if !x.valid() {
		t.Fatal("complete proof rejected")
	}
	out, _ := json.Marshal(x.status())
	for _, secret := range []string{x.Binding.OwnerSID, x.Binding.Executable, x.Binding.SHA256, x.Consent.TokenHash, "core_pid", "helper_pid"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("status leaked %s", secret)
		}
	}
}
func TestLocalRestartTaskHasOneFixedNoTriggerAction(t *testing.T) {
	j := restartFixture()
	text := restartTaskXML(j)
	if e := validateRestartTask(text, j); e != nil {
		t.Fatal(e)
	}
	changes := map[string]string{"hard_kill": strings.Replace(text, "<AllowHardTerminate>false", "<AllowHardTerminate>true", 1), "timelimit": strings.Replace(text, "PT0S", "PT1M", 1), "demand_disabled": strings.Replace(text, "<AllowStartOnDemand>true", "<AllowStartOnDemand>false", 1), "trigger": strings.Replace(text, "<Triggers/>", "<Triggers><BootTrigger/></Triggers>", 1), "group": strings.Replace(text, "<LogonType>", "<GroupId>S-1-5-32-544</GroupId><LogonType>", 1), "argument": strings.Replace(text, LocalRestartArgument, "--uninstall", 1), "extra_action": strings.Replace(text, "</Actions>", "<ComHandler/></Actions>", 1), "duplicate_setting": strings.Replace(text, "</Settings>", "<AllowHardTerminate>false</AllowHardTerminate></Settings>", 1), "working_dir": strings.Replace(text, "</Exec>", "<WorkingDirectory>C:\\foreign</WorkingDirectory></Exec>", 1)}
	for name, x := range changes {
		t.Run(name, func(t *testing.T) {
			if validateRestartTask(x, j) == nil {
				t.Fatal("changed task accepted")
			}
		})
	}
	if restartTaskHash(text) == restartTaskHash(text+" ") {
		t.Fatal("task readback identity not exact")
	}
}
func TestLocalRestartCoreReadinessIsNotPipeOrACK(t *testing.T) {
	for _, b := range []string{`{}`, `{"event":"program-exit-complete"}`, `{"version":"1","display":{"desktop":{"event":"status","version":"1","program_exit":{"phase":"ready"}}}}`} {
		if restartCoreSnapshotReadable([]byte(b), "1") {
			t.Fatalf("false completed proof: %s", b)
		}
	}
	if !restartCoreSnapshotReadable([]byte(`{"version":"1","display":{"desktop":{"event":"status","version":"1","program_exit":{"phase":"idle"}}}}`), "1") {
		t.Fatal("new idle snapshot rejected")
	}
}

func TestLocalRestartAbandonedClaimNeverUsesPipeLoss(t *testing.T) {
	j := restartFixture()
	if restartAbandoned(j, true, true) || !restartPreparedSupersedable(j) {
		t.Fatal("unclaimed request requires explicit replacement")
	}
	j.Phase = "running"
	j.HelperPID = 9
	j.HelperCreation = 10
	if restartPreparedSupersedable(j) {
		t.Fatal("claimed request replaced")
	}
	for _, p := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		if restartAbandoned(j, p[0], p[1]) {
			t.Fatal("unknown or live helper abandoned")
		}
	}
	if !restartAbandoned(j, true, true) {
		t.Fatal("confirmed dead helper not reconciled")
	}
	j.Phase = "completed"
	if restartAbandoned(j, true, true) {
		t.Fatal("terminal state changed")
	}
}

func TestLocalRestartAdmissionIsOneUseAndExactPeer(t *testing.T) {
	j := restartFixture()
	j.Phase = "running"
	j.HelperPID = 30
	j.HelperCreation = 40
	j.TaskSHA = strings.Repeat("d", 64)
	matches := func(x localRestartJob) bool {
		return restartAdmissionMatches(x, j.ID, j.Binding.OwnerSID, j.Session, j.HelperPID, j.HelperCreation, j.CorePID)
	}
	if !matches(j) {
		t.Fatal("valid unconsumed helper rejected")
	}
	for name, mutate := range map[string]func(*localRestartJob){"consumed": func(j *localRestartJob) { j.Admitted = true }, "different_owner": func(j *localRestartJob) { j.Binding.OwnerSID = "S-1-5-21-4-5-6-1001" }, "different_session": func(j *localRestartJob) { j.Session++ }, "reused_pid": func(j *localRestartJob) { j.HelperCreation++ }, "another_pid": func(j *localRestartJob) { j.HelperPID++ }, "another_core": func(j *localRestartJob) { j.CorePID++ }, "not_claimed": func(j *localRestartJob) { j.Phase = "prepared"; j.HelperPID = 0; j.HelperCreation = 0 }} {
		t.Run(name, func(t *testing.T) {
			x := j
			mutate(&x)
			if matches(x) {
				t.Fatal("invalid peer/claim admitted")
			}
		})
	}
}

func TestLocalRestartAdmissionReadbackOnlyChangesConsumedBit(t *testing.T) {
	j := restartFixture()
	j.Phase = "running"
	j.HelperPID = 30
	j.HelperCreation = 40
	j.TaskSHA = strings.Repeat("d", 64)
	after := j
	after.Admitted = true
	if !restartAdmissionReceipt(j, after) {
		t.Fatal("exact admission rejected")
	}
	for name, mutate := range map[string]func(*localRestartJob){"source": func(j *localRestartJob) { j.Binding.SHA256 = strings.Repeat("e", 64) }, "session": func(j *localRestartJob) { j.Session++ }, "helper_creation": func(j *localRestartJob) { j.HelperCreation++ }, "task": func(j *localRestartJob) { j.TaskSHA = strings.Repeat("f", 64) }, "phase": func(j *localRestartJob) { j.Phase = "ready" }, "consent": func(j *localRestartJob) { j.Consent.Revision++ }} {
		t.Run(name, func(t *testing.T) {
			x := after
			mutate(&x)
			if restartAdmissionReceipt(j, x) {
				t.Fatal("admission replaced protected context")
			}
		})
	}
}
