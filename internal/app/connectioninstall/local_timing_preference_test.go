//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalTimingPreferenceSeparateAndOwnerBound(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	other := "S-1-5-21-1-2-3-1002"
	path, err := localTimingPreferenceName(sid)
	if err != nil {
		t.Fatal(err)
	}
	master, _ := localDebugPreferenceName(sid)
	otherPath, _ := localTimingPreferenceName(other)
	if path == master || path == otherPath || strings.Contains(path, sid) {
		t.Fatal(path, master, otherPath)
	}
	for _, mode := range []string{"normal", "fast", "delayed"} {
		b, _ := json.Marshal(localTimingPreference{Schema: 1, OwnerSID: sid, Mode: mode})
		got, e := decodeLocalTimingPreference(b, sid)
		if e != nil || got != mode {
			t.Fatal(got, e)
		}
		if _, e = decodeLocalTimingPreference(b, other); e == nil {
			t.Fatal("foreign owner accepted")
		}
		var fields map[string]any
		_ = json.Unmarshal(b, &fields)
		if len(fields) != 3 {
			t.Fatal(fields)
		}
	}
}
func TestLocalTimingPreferenceRejectsMalformedUnknownAndOversized(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	good := `{"schema":1,"owner_sid":"` + sid + `","mode":"delayed"}`
	for _, body := range []string{`{}`, strings.Replace(good, `"mode":"delayed"`, `"mode":"other"`, 1), strings.Replace(good, `"schema":1`, `"schema":2`, 1), strings.Replace(good, `"mode":"delayed"`, `"mode":null`, 1), strings.Replace(good, `"mode":"delayed"`, `"mode":"fast","token":"forbidden"`, 1), good + `{}`, strings.Repeat(" ", 1025) + good} {
		if _, e := decodeLocalTimingPreference([]byte(body), sid); e == nil {
			t.Fatal("accepted invalid data", body)
		}
	}
	if _, e := localTimingPreferenceName(`..\outside`); e == nil {
		t.Fatal("invalid owner accepted")
	}
}
