package connectioninstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPreparedDiagnosticPreservesExactAuthorizationPolicy(t *testing.T) {
	owner := "S-1-5-21-1-2-3-1001"
	for _, next := range []string{"0.8.100", "0.8.98", "0.8.97", "bad"} {
		for _, previous := range []string{"0.8.98", "bad", ""} {
			for _, user := range []string{owner, "S-1-5-18", "S-1-5-21-4-5-6-1001"} {
				for _, bound := range []bool{false, true} {
					for _, same := range []bool{false, true} {
						problem := preparedPolicyProblem(next, previous, user, owner, bound, same)
						if (problem == "") != preparedInstallPolicy(next, previous, user, owner, bound, same) {
							t.Fatalf("diagnosis changed gate for next=%q previous=%q bound=%v same=%v", next, previous, bound, same)
						}
					}
				}
			}
		}
	}
	if got := preparedPolicyProblem("0.8.100", "0.8.100", owner, owner, true, true); got != "PREPARED_INSTALL_SOURCE_ALREADY_CURRENT" {
		t.Fatal("repeat click still hides same-source refusal", got)
	}
}

func TestPreparedDiagnosticsBoundAndExcludePrivateInput(t *testing.T) {
	private := `C:\Users\private\job-content S-1-5-21-1-2-3-1001`
	for _, value := range []string{private, strings.Repeat("A", 1000), "phase\nextra", ""} {
		o := boundedPreparedObservation(value, value, value, 5)
		b, err := json.Marshal(o)
		if err != nil || len(b) > 256 || strings.Contains(string(b), private) || o.Version != "" || o.Phase != "UNKNOWN" || o.Code != "PREPARED_INSTALL_VERIFICATION_FAILED" || !o.ObservationOnly {
			t.Fatal("unbounded/private diagnostic", string(b), err)
		}
	}
	o := boundedPreparedObservation("0.8.100", "OWNER_VERSION", "PREPARED_INSTALL_SOURCE_ALREADY_CURRENT", 0)
	if o.Version != "0.8.100" || o.Phase != "OWNER_VERSION" || o.Code != "PREPARED_INSTALL_SOURCE_ALREADY_CURRENT" {
		t.Fatal("fixed useful code lost", o)
	}
}
