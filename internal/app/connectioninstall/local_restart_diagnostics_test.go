//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

type restartFakeHRESULT uint32

func (e restartFakeHRESULT) Error() string         { return `native private C:\username\secret token` }
func (e restartFakeHRESULT) NativeHRESULT() uint32 { return uint32(e) }
func TestLocalRestartDiagnosticRetainsNumericFirstCauseOnly(t *testing.T) {
	original := restartDiagnostic("create", "register", fmt.Errorf("private task XML: %w", restartFakeHRESULT(0x80070005)))
	wrapped := &restartTaskFailure{diagnostic: original, err: errors.New("private XML")}
	if got := restartDiagnostic("prepare", "receipt_save", wrapped); got != original || got.NativeKind != "HRESULT" || got.NativeCode != 0x80070005 {
		t.Fatalf("lost native stage: %+v", got)
	}
	j := restartFixture()
	j.Phase = "failed"
	j.Error = "LOCAL_RESTART_TASK_CLEANUP_FAILED"
	j.Diagnostic = original
	j.CleanupDiagnostic = restartDiagnostic("delete", "delete", syscall.Errno(5))
	status := j.status()
	status.TaskInspection = &LocalRestartTaskInspection{Exists: true, ReadComplete: true, NameMatches: true, PathMatches: true, Enabled: true, State: 4, ReceiptHashPresent: true, HashMatches: true, TaskMismatch: 0xffff, PrincipalUserForm: restartPrincipalUserForm(strings.Replace(restartTaskXML(j), j.Binding.OwnerSID, `MACHINE\private-user`, 1)), PrincipalResolutionChecked: true, PrincipalSIDMatches: true, Diagnostic: original}
	b, _ := json.Marshal(status)
	for _, secret := range []string{"private", "username", "secret", "token", j.Binding.OwnerSID, j.Binding.Executable} {
		if strings.Contains(string(b), secret) {
			t.Fatal("private failure detail leaked")
		}
	}
	if len(b) > 4096 {
		t.Fatal("status budget")
	}
	b, _ = json.Marshal(j)
	got, e := decodeRestartJob(b)
	if e != nil || got != j {
		t.Fatalf("diagnostic receipt mismatch %v", e)
	}
	if got.Diagnostic == got.CleanupDiagnostic || got.Diagnostic != original {
		t.Fatal("cleanup replaced first failure")
	}
	legacy := restartFixture()
	legacy.Phase = "failed"
	legacy.Error = "LOCAL_RESTART_TASK_FAILED"
	b, _ = json.Marshal(legacy)
	if strings.Contains(string(b), "diagnostic") {
		t.Fatal("zero diagnostics changed legacy encoding")
	}
	if _, e = decodeRestartJob(b); e != nil {
		t.Fatal("old failed receipt unreadable")
	}
	for _, d := range []LocalRestartDiagnostic{{Operation: "exec arbitrary", Stage: "run", Cause: "OPERATION_FAILED"}, {Operation: "run", Stage: `C:\secret`, Cause: "OPERATION_FAILED"}, {Operation: "run", Stage: "run", Cause: "UNKNOWN_TEXT"}, {Operation: "run", Stage: "run", Cause: "NATIVE_FAILURE", NativeKind: "HRESULT", NativeCode: 0}, {Operation: "run", Stage: "run", Cause: "TASK_XML_MISMATCH", TaskMismatch: 1 << 16}} {
		if restartDiagnosticValid(d) {
			t.Fatal("unbounded diagnostic accepted")
		}
	}
}
func TestLocalRestartTaskMismatchIdentifiesSafePredicates(t *testing.T) {
	j := restartFixture()
	text := restartTaskXML(j)
	for i, field := range []string{"MultipleInstancesPolicy", "DisallowStartIfOnBatteries", "StopIfGoingOnBatteries", "AllowHardTerminate", "AllowStartOnDemand", "ExecutionTimeLimit", "Enabled"} {
		start := "<" + field + ">"
		end := "</" + field + ">"
		a := strings.Index(text, start) + len(start)
		z := strings.Index(text, end)
		bad := text[:a] + "changed" + text[z:]
		if mask := restartTaskMismatch(bad, j); mask&(1<<uint(8+i)) == 0 {
			t.Fatalf("field %d lacks specific mismatch: %x", i, mask)
		}
	}
	changed := strings.Replace(text, j.Binding.OwnerSID, `MACHINE\private-user`, 1)
	if mask := restartTaskMismatch(changed, j); mask&(1<<15) == 0 {
		t.Fatal("raw owner representation difference invisible")
	}
	resolve := func(s string) (string, error) {
		if s != `MACHINE\private-user` {
			t.Fatal("unexpected resolver argument")
		}
		return j.Binding.OwnerSID, nil
	}
	mask, checked, matched := restartResolvedTaskMismatch(changed, j, resolve)
	if mask != 0 || !checked || !matched {
		t.Fatalf("same resolved SID rejected: %x", mask)
	}
	mask, checked, matched = restartResolvedTaskMismatch(changed, j, func(string) (string, error) { return "S-1-5-21-9-8-7-1001", nil })
	if mask == 0 || !checked || matched {
		t.Fatal("foreign owner accepted")
	}
	mask, checked, matched = restartResolvedTaskMismatch(changed, j, func(string) (string, error) { return "", errors.New("private") })
	if mask == 0 || checked || matched {
		t.Fatal("unresolved owner accepted")
	}
	bad := strings.Replace(changed, "HighestAvailable", "LeastPrivilege", 1)
	mask, _, matched = restartResolvedTaskMismatch(bad, j, resolve)
	if mask&32 == 0 || !matched {
		t.Fatal("SID normalization cleared different privilege")
	}
	malformed := strings.Replace(changed, "<Triggers/>", "<Triggers><BootTrigger/></Triggers>", 1)
	called := false
	mask, _, _ = restartResolvedTaskMismatch(malformed, j, func(string) (string, error) { called = true; return j.Binding.OwnerSID, nil })
	if mask == 0 || called {
		t.Fatal("invalid template resolved or accepted")
	}
}
func TestLocalRestartRetentionNeverClaimsUnknownTask(t *testing.T) {
	j := restartFixture()
	j.Phase = "failed"
	j.Error = "LOCAL_RESTART_TASK_FAILED"
	if !restartRetainUnverified(j) {
		t.Fatal("50 never-claimed failed record cannot be retained")
	}
	for _, change := range []func(*localRestartJob){func(j *localRestartJob) { j.TaskSHA = strings.Repeat("d", 64) }, func(j *localRestartJob) { j.HelperPID = 2; j.HelperCreation = 4 }, func(j *localRestartJob) { j.Admitted = true }, func(j *localRestartJob) { j.Phase = "prepared" }} {
		x := j
		change(&x)
		if restartRetainUnverified(x) {
			t.Fatal("claimed/verified/active task was treated as unknown unclaimed")
		}
	}
}

func TestLocalRestartTaskSchemaDefaultsAndBooleanLexicalValues(t *testing.T) {
	j := restartFixture()
	original := restartTaskXML(j)
	withoutTrueDefaults := strings.NewReplacer(
		"<AllowStartOnDemand>true</AllowStartOnDemand>", "",
		"<Enabled>true</Enabled>", "",
	).Replace(original)
	if err := validateRestartTask(withoutTrueDefaults, j); err != nil {
		t.Fatalf("schema-default true settings rejected: %v", err)
	}
	if restartTaskHash(withoutTrueDefaults) == restartTaskHash(original) {
		t.Fatal("semantic normalization weakened exact readback hash")
	}
	for _, field := range []struct {
		name, expected string
		bit            uint32
	}{
		{"DisallowStartIfOnBatteries", "false", 1 << 9},
		{"StopIfGoingOnBatteries", "false", 1 << 10},
		{"AllowHardTerminate", "false", 1 << 11},
		{"AllowStartOnDemand", "true", 1 << 12},
		{"Enabled", "true", 1 << 14},
	} {
		for _, lexical := range []string{"absent", "true", "false", "1", "0", "", "TRUE", "False", "yes", "01", " 1\n", "\t0\r", "tr ue", "<Unknown>true</Unknown>"} {
			t.Run(field.name+"/"+lexical, func(t *testing.T) {
				element := "<" + field.name + ">" + field.expected + "</" + field.name + ">"
				replacement := "<" + field.name + ">" + lexical + "</" + field.name + ">"
				if lexical == "absent" {
					replacement = ""
				}
				text := strings.Replace(original, element, replacement, 1)
				want := field.expected == "true" && (lexical == "absent" || lexical == "true" || lexical == "1" || lexical == " 1\n") || field.expected == "false" && (lexical == "false" || lexical == "0" || lexical == "\t0\r")
				mask := restartTaskMismatch(text, j)
				if want && mask != 0 || !want && mask&field.bit == 0 {
					t.Fatalf("mask=%x accepted=%v", mask, want)
				}
				if got := validateRestartTask(text, j) == nil; got != want {
					t.Fatalf("full task accepted=%v want=%v", got, want)
				}
			})
		}
	}
	for _, field := range []string{"AllowStartOnDemand", "Enabled"} {
		duplicate := strings.Replace(original, "</Settings>", "<"+field+">1</"+field+"></Settings>", 1)
		if validateRestartTask(duplicate, j) == nil {
			t.Fatalf("duplicate %s accepted", field)
		}
	}
	for _, element := range []string{"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>", "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"} {
		if validateRestartTask(strings.Replace(withoutTrueDefaults, element, "", 1), j) == nil {
			t.Fatal("other missing policy accepted")
		}
	}
}

func TestLocalRestartRetentionPreservesRecoveryBeforeReplacingCurrent(t *testing.T) {
	j := restartFixture()
	j.Phase = "failed"
	j.Error = "LOCAL_RESTART_TASK_FAILED"
	for _, kind := range []string{"success", "existing_same", "existing_changed", "read_error", "limit", "write_failure", "readback_changed"} {
		t.Run(kind, func(t *testing.T) {
			stored := localRestartJob{}
			present := false
			writes := 0
			reads := 0
			if kind == "existing_same" || kind == "existing_changed" {
				stored = j
				present = true
			}
			if kind == "existing_changed" {
				stored.Consent.Revision++
			}
			read := func() (localRestartJob, bool, error) {
				reads++
				if kind == "read_error" {
					return stored, false, errors.New("read denied")
				}
				out := stored
				if kind == "readback_changed" && reads > 1 {
					out.Consent.Revision++
				}
				return out, present, nil
			}
			count := func() (int, error) {
				if kind == "limit" {
					return 16, nil
				}
				return 0, nil
			}
			write := func(x localRestartJob) error {
				writes++
				if kind == "write_failure" {
					return errors.New("disk full")
				}
				stored = x
				present = true
				return nil
			}
			e := retainRestartReceipt(j, read, count, write)
			success := kind == "success" || kind == "existing_same"
			if (e == nil) != success {
				t.Fatalf("result %v", e)
			}
			if kind == "existing_same" || kind == "existing_changed" || kind == "read_error" || kind == "limit" {
				if writes != 0 {
					t.Fatal("wrote over unknown/unreadable/existing retention")
				}
			}
			if kind == "success" && (writes != 1 || reads != 2 || stored != j) {
				t.Fatal("retention lacks exact readback")
			}
		})
	}
}
