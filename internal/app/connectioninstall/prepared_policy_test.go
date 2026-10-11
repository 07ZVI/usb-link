package connectioninstall

import (
	"strings"
	"testing"
)

func TestPreparedInstallOwnerAndVersionCannotBorrowBinding(t *testing.T) {
	owner := "S-1-5-21-1-2-3-1001"
	if !preparedInstallPolicy("0.8.100", "0.8.98", owner, owner, true, false) {
		t.Fatal("new owned candidate rejected")
	}
	for _, v := range []string{"0.8.98", "0.8.97", "bad"} {
		if preparedInstallPolicy(v, "0.8.98", owner, owner, true, false) {
			t.Fatal("not newer", v)
		}
	}
	if preparedInstallPolicy("0.8.100", "0.8.98", owner, owner, true, true) || preparedInstallPolicy("0.8.100", "0.8.98", owner, "S-1-5-21-9-9-9-1", true, false) || preparedInstallPolicy("0.8.100", "0.8.98", "S-1-5-18", owner, false, false) {
		t.Fatal("foreign/system/self binding accepted")
	}
	if !preparedInstallPolicy("0.8.100", "", owner, "", false, false) {
		t.Fatal("owned first installation rejected")
	}
}
func TestPreparedInstallTerminalFailedWithoutCandidateDoesNotBlock(t *testing.T) {
	if !preparedJobIdle("failed", 0, 0, "") {
		t.Fatal("unattempted rejected stage became permanent fence")
	}
	for _, s := range []string{"starting", "staged", "installing", "rollback", "rollback_failed", "manual_recovery_required", "unknown", ""} {
		if preparedJobIdle(s, 0, 0, "") {
			t.Fatal("pending/unknown job considered idle", s)
		}
	}
	if preparedJobIdle("failed", 1, 0, "") || preparedJobIdle("failed", 0, 1, "") || preparedJobIdle("failed", 0, 0, "candidate.exe") {
		t.Fatal("attempted failed outcome silently ignored")
	}
	for _, s := range []string{"complete", "declined", "cancelled"} {
		if !preparedJobIdle(s, 1, 2, "source") {
			t.Fatal("terminal journal rejected", s)
		}
	}
}
func TestPreparedInstallJournalRejectsShadowedAndUnboundedMetadata(t *testing.T) {
	if !preparedJournalUnique([]byte(`{"id":"a","status":"failed","Manifest":{"Version":"0.8.99"}}`)) {
		t.Fatal("normal protected metadata rejected")
	}
	for _, s := range []string{`{"status":"starting","Status":"failed"}`, `{"Manifest":{"Version":"0.8.99","version":"0.8.100"}}`, `{"status":"failed"}{}`, strings.Repeat(" ", 32769)} {
		if preparedJournalUnique([]byte(s)) {
			t.Fatal("ambiguous journal accepted")
		}
	}
}
