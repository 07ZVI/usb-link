package netconfig

import (
	"errors"
	"strings"
	"testing"
)

func TestSessionRuleAbsenceQueryExactScope(t *testing.T) {
	token := strings.Repeat("a", 24)
	names := []string{}
	for _, suffix := range []string{"ICMP", "BENCH", "SUN-TCP", "SUN-UDP", "FILES"} {
		names = append(names, "Suhang-USB-Phase2-"+token+"-"+suffix)
	}
	q, err := sessionRuleAbsenceQuery(token, names)
	if err != nil {
		t.Fatal(err)
	}
	want := "SELECT * FROM MSFT_NetFirewallRule WHERE InstanceID='Suhang-USB-Phase2-" + token + "-ICMP' OR InstanceID='Suhang-USB-Phase2-" + token + "-BENCH' OR InstanceID='Suhang-USB-Phase2-" + token + "-SUN-TCP' OR InstanceID='Suhang-USB-Phase2-" + token + "-SUN-UDP' OR InstanceID='Suhang-USB-Phase2-" + token + "-FILES'"
	if q != want {
		t.Fatalf("unexpected exact query: %s", q)
	}
	for _, bad := range []string{"", strings.Repeat("a", 23), strings.Repeat("a", 25), strings.Repeat("A", 24), "' OR 1=1", token + "\n", strings.Repeat("g", 24)} {
		if q, e := sessionRuleAbsenceQuery(bad, names); e == nil || q != "" {
			t.Fatal("unsafe selector accepted")
		}
	}
}
func TestSessionRuleAbsenceRequiresZeroCompleteCount(t *testing.T) {
	for _, n := range []int32{-1, 1, 2, 5, 1000} {
		if sessionRuleAbsenceCount(n, nil) == nil {
			t.Fatalf("accepted %d", n)
		}
	}
	if sessionRuleAbsenceCount(0, nil) != nil {
		t.Fatal("zero rejected")
	}
	failure := errors.New("read failed")
	if !errors.Is(sessionRuleAbsenceCount(0, failure), failure) {
		t.Fatal("error hidden")
	}
}

func TestSessionAbsenceQueryUsesEverySuppliedObligation(t *testing.T) {
	token := strings.Repeat("b", 24)
	prefix := "Suhang-USB-Phase2-" + token + "-"
	q, e := sessionRuleAbsenceQuery(token, []string{prefix + "FILES", prefix + "FUTURE-RULE"})
	if e != nil || !strings.Contains(q, "InstanceID='"+prefix+"FUTURE-RULE'") {
		t.Fatal("obligation silently omitted")
	}
	for _, names := range [][]string{nil, {prefix + "FILES", prefix + "FILES"}, {prefix + "FILES' OR 1=1"}, {"Suhang-USB-Phase2-" + strings.Repeat("a", 24) + "-FILES"}, {prefix + "FILES\n"}, make([]string, 17)} {
		if _, e := sessionRuleAbsenceQuery(token, names); e == nil {
			t.Fatal("invalid scope accepted")
		}
	}
}
