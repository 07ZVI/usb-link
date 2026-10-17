//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalWPDTracePreferenceOwnerAndIndependentSchema(t *testing.T) {
	sid, other := "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	name, err := localWPDTracePreferenceName(sid)
	if err != nil {
		t.Fatal(err)
	}
	master, _ := localDebugPreferenceName(sid)
	timing, _ := localTimingPreferenceName(sid)
	foreign, _ := localWPDTracePreferenceName(other)
	if name == master || name == timing || name == foreign || strings.Contains(name, sid) {
		t.Fatal("preference namespace or owner collision")
	}
	for _, enabled := range []bool{false, true} {
		b, _ := json.Marshal(localWPDTracePreference{Schema: 1, OwnerSID: sid, Enabled: &enabled})
		got, e := decodeLocalWPDTracePreference(b, sid)
		if e != nil || got != enabled {
			t.Fatal(got, e)
		}
		if _, e := decodeLocalWPDTracePreference(b, other); e == nil {
			t.Fatal("foreign owner accepted")
		}
	}
}

func TestLocalWPDTracePreferenceRejectsIncompleteOrForeignData(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	good := `{"schema":1,"owner_sid":"` + sid + `","enabled":true}`
	for _, body := range []string{`{}`, strings.Replace(good, `,"enabled":true`, "", 1), strings.Replace(good, `true`, `null`, 1), strings.Replace(good, `true`, `"true"`, 1), strings.Replace(good, `"schema":1`, `"schema":2`, 1), strings.Replace(good, `true`, `true,"mode":"fast"`, 1), good + `{}`, strings.Repeat(" ", 1025) + good} {
		if _, err := decodeLocalWPDTracePreference([]byte(body), sid); err == nil {
			t.Fatal("invalid preference accepted", body)
		}
	}
	if _, err := localWPDTracePreferenceName(`..\outside`); err == nil {
		t.Fatal("invalid owner accepted")
	}
}
