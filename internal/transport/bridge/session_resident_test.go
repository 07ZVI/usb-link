package bridge

import (
	"encoding/json"
	"testing"
)

func TestResidentSessionNeverAdoptsLegacyOrRetainedTokenSemantics(t *testing.T) {
	v := OwnedSession{Version: ResidentSessionVersion, GUID: retainedMacGUID, Token: "0123456789abcdef01234567", Status: "ACTIVE"}
	b, _ := json.Marshal(v)
	got, e := ParseResidentSession(b)
	if e != nil || VerifyLiveResidentSession(v, got) != nil {
		t.Fatal(e)
	}
	if _, e = ParseOrdinarySession(b); e == nil {
		t.Fatal("resident record accepted by legacy parser")
	}
	for _, bad := range []OwnedSession{
		{Version: SessionVersion, GUID: v.GUID, Token: v.Token, Status: v.Status},
		{Version: RetainedSessionVersion, GUID: v.GUID, Token: v.Token, Status: v.Status},
		{Version: v.Version, GUID: v.GUID, Token: v.Token, Status: v.Status, Retained: &RetainedAddress{}},
		{Version: v.Version, GUID: v.GUID, Token: v.Token, Status: "CLEAN"},
	} {
		if VerifyLiveResidentSession(v, bad) == nil {
			t.Fatal("foreign or completed record adopted", bad)
		}
	}
	for _, b := range []string{`{"version":"0.8.109-resident-firewall","guid":"{A4611646-E050-4D25-B83E-633A5598F302}","token":"0123456789abcdef01234567","status":"ACTIVE","status":"CLEAN"}`, `{"version":"0.8.109-resident-firewall","guid":"{A4611646-E050-4D25-B83E-633A5598F302}","token":"0123456789abcdef01234567","status":"ACTIVE","firewall":true}`} {
		if _, e := ParseResidentSession([]byte(b)); e == nil {
			t.Fatal("ambiguous record accepted")
		}
	}
}
