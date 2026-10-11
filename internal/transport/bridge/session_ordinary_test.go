package bridge

import (
	"encoding/json"
	"strings"
	"testing"
)

func ordinarySessionFixture() (OwnedSession, []byte) {
	v := NewOwnedSession(retainedMacGUID, strings.Repeat("a", 24))
	b, _ := json.Marshal(v)
	return v, b
}

func TestOrdinarySessionExactFieldsAndTypes(t *testing.T) {
	expected, b := ordinarySessionFixture()
	got, err := ParseOrdinarySession(b)
	if err != nil || VerifyLiveOrdinarySession(expected, got) != nil {
		t.Fatalf("valid current ordinary record rejected: %v", err)
	}
	for _, bad := range []string{
		"", "null", "[]", string(b) + " {}", string(b) + " true",
		strings.Replace(string(b), `"status":"ACTIVE"`, `"status":"ACTIVE","status":"ACTIVE"`, 1),
		strings.Replace(string(b), `"guid":`, `"GUID":`, 1),
		strings.Replace(string(b), `"token":"`+expected.Token+`"`, `"token":null`, 1),
		strings.Replace(string(b), `"status":"ACTIVE"`, `"status":1`, 1),
		strings.Replace(string(b), `"status":"ACTIVE"`, `"status":"WAITING"`, 1),
		strings.Replace(string(b), `"status":"ACTIVE"`, `"status":"ACTIVE","retained_address":null`, 1),
		strings.Replace(string(b), SessionVersion, RetainedSessionVersion, 1),
		strings.Replace(string(b), expected.GUID, "{00000000-0000-0000-0000-000000000000}", 1),
		strings.Replace(string(b), expected.Token, strings.ToUpper(expected.Token), 1),
		strings.Replace(string(b), expected.Token, strings.Repeat("a", 23), 1),
		string(b) + strings.Repeat(" ", 4097),
	} {
		if _, err := ParseOrdinarySession([]byte(bad)); err == nil {
			t.Fatal("invalid ordinary record accepted", bad)
		}
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(b, &fields)
	for key := range fields {
		missing := map[string]json.RawMessage{}
		for k, v := range fields {
			if k != key {
				missing[k] = v
			}
		}
		bad, _ := json.Marshal(missing)
		if _, err := ParseOrdinarySession(bad); err == nil {
			t.Fatal("missing field accepted", key)
		}
	}
}

func TestOrdinaryLiveCleanupRejectsDriftAndOldSessions(t *testing.T) {
	current, _ := ordinarySessionFixture()
	for _, field := range []string{"version", "guid", "token", "status", "retained"} {
		observed := current
		switch field {
		case "version":
			observed.Version = RetainedSessionVersion
		case "guid":
			observed.GUID = "{00000000-0000-0000-0000-000000000000}"
		case "token":
			observed.Token = strings.Repeat("b", 24)
		case "status":
			observed.Status = "CLEANUP_REQUIRED"
		case "retained":
			observed.Retained = &RetainedAddress{}
		}
		if VerifyLiveOrdinarySession(current, observed) == nil {
			t.Fatal("changed live record accepted", field)
		}
	}
	for _, status := range []string{"CLEAN", "CLEANUP_REQUIRED"} {
		old := current
		old.Status = status
		b, _ := json.Marshal(old)
		parsed, err := ParseOrdinarySession(b)
		if err != nil {
			t.Fatal("valid completed record rejected by parser", err)
		}
		if VerifyLiveOrdinarySession(old, parsed) == nil {
			t.Fatal("old record adopted as live cleanup lease", status)
		}
	}
	if VerifyLiveOrdinarySession(OwnedSession{}, current) == nil {
		t.Fatal("unbound expected lease accepted")
	}
}
