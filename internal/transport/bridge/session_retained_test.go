package bridge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRetainedSessionIsCompleteAndCannotDowngradeFormat(t *testing.T) {
	v := NewOwnedSession(retainedMacGUID, strings.Repeat("a", 24))
	v.Version = RetainedSessionVersion
	v.Retained = &RetainedAddress{7, 9, 11, "legacy", strings.Repeat("b", 64), false}
	b, _ := json.Marshal(v)
	if _, e := ParseRetainedSession(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), `,"network_prepared":false`, "", 1), strings.Replace(string(b), `"network_prepared":false`, `"network_prepared":null`, 1), strings.Replace(string(b), `"luid":9`, `"luid":0`, 1), strings.Replace(string(b), `"luid":9`, `"luid":9,"luid":10`, 1), strings.Replace(string(b), RetainedSessionVersion, SessionVersion, 1), string(b) + " {}"} {
		if _, e := ParseRetainedSession([]byte(bad)); e == nil {
			t.Fatal("invalid retained journal accepted", bad)
		}
	}
}
