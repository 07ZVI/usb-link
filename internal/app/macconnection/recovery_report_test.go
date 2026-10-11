package macconnection

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecoveryMessageDoesNotMisidentifyRunningBridge(t *testing.T) {
	for _, code := range []string{"MAC_RECOVERY_RECORD_INVALID", "MAC_ADAPTER_RECOVERY_UNCONFIRMED", "MAC_RULE_RECOVERY_UNCONFIRMED", "MAC_BRIDGE_LOCK_UNAVAILABLE", "MAC_RECOVERY_JOURNAL_NOT_CLEARED"} {
		if s := RecoveryMessage(code + ": system error"); strings.Contains(s, "請从舊版") || strings.Contains(s, "請從舊版") {
			t.Fatalf("%s incorrectly asks to exit a running bridge: %s", code, s)
		}
	}
	if !strings.Contains(RecoveryMessage("MAC_BRIDGE_STILL_RUNNING: exists"), "只關閉視窗") {
		t.Fatal("running bridge needs explicit background exit guidance")
	}
}
func TestRecoveryOutputBoundedAndSerialized(t *testing.T) {
	var b recoveryOutput
	input := []byte(strings.Repeat("x", 20000))
	if n, e := b.Write(input); n != len(input) || e != nil {
		t.Fatal(n, e)
	}
	b.Write([]byte("extra"))
	if b.Len() != 16384 {
		t.Fatal(b.Len())
	}
	report := RecoveryReport{Error: "MAC_ADAPTER_RECOVERY_UNCONFIRMED", Entries: []RecoveryEntry{{Runtime: "mac-runtime-v4", Error: "query failed", Output: "Get-NetAdapter unavailable"}}}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var restored RecoveryReport
	if err = json.Unmarshal(data, &restored); err != nil || len(restored.Entries) != 1 || restored.Entries[0].Output != "Get-NetAdapter unavailable" {
		t.Fatal(string(data), err)
	}
}
