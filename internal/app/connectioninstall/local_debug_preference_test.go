//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalDebugPreferenceBoundToUserAndContainsNoCredentials(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	other := "S-1-5-21-1-2-3-1002"
	for _, on := range []bool{false, true} {
		b, err := json.Marshal(localDebugPreference{Schema: 1, OwnerSID: sid, Enabled: &on})
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeLocalDebugPreference(b, sid)
		if err != nil || got != on {
			t.Fatal(got, err)
		}
		if _, err = decodeLocalDebugPreference(b, other); err == nil {
			t.Fatal("borrowed another user's authorization")
		}
		var fields map[string]any
		_ = json.Unmarshal(b, &fields)
		if len(fields) != 3 {
			t.Fatal("preference includes non-intent fields", fields)
		}
	}
	a, _ := localDebugPreferenceName(sid)
	b, _ := localDebugPreferenceName(other)
	if a == b || strings.Contains(a, sid) {
		t.Fatal("preference keys not scoped", a, b)
	}
}

func TestLocalDebugPreferenceRejectsMalformedAndCredentialMaterial(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	valid := `{"schema":1,"owner_sid":"` + sid + `","enabled":true}`
	for _, body := range []string{"", `{}`, strings.Replace(valid, `"enabled":true`, `"enabled":null`, 1), strings.Replace(valid, `"schema":1`, `"schema":2`, 1), valid + `{}`, strings.Replace(valid, `"enabled":true`, `"enabled":true,"token":"retained"`, 1), strings.Repeat(" ", 1025) + valid} {
		if _, err := decodeLocalDebugPreference([]byte(body), sid); err == nil {
			t.Fatal("accepted invalid preference", body)
		}
	}
	if _, err := localDebugPreferenceName(`..\foreign`); err == nil {
		t.Fatal("accepted invalid SID")
	}
}
