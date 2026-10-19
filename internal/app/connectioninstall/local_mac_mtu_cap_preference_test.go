//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalMacMTUCapPreferenceRoundTripOwnerAndNamespace(t *testing.T) {
	sid, other := "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	name, err := localMacMTUCapPreferenceName(sid)
	if err != nil {
		t.Fatal(err)
	}
	master, _ := localDebugPreferenceName(sid)
	direct, _ := localNCMDirectPreferenceName(sid)
	foreign, _ := localMacMTUCapPreferenceName(other)
	if name == master || name == direct || name == foreign || strings.Contains(name, sid) {
		t.Fatal("preference namespace or owner collision")
	}
	for _, value := range []string{"auto", "9000", "1500"} {
		b, _ := json.Marshal(localMacMTUCapPreference{Schema: 1, OwnerSID: sid, Cap: value})
		got, e := decodeLocalMacMTUCapPreference(b, sid)
		if e != nil || got != value {
			t.Fatal(value, got, e)
		}
		if _, e := decodeLocalMacMTUCapPreference(b, other); e == nil {
			t.Fatal("foreign owner accepted")
		}
	}
}

func TestLocalMacMTUCapPreferenceRejectsInvalidData(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	good := `{"schema":1,"owner_sid":"` + sid + `","cap":"9000"}`
	for _, body := range []string{`{}`, strings.Replace(good, `,"cap":"9000"`, "", 1), strings.Replace(good, `"9000"`, `""`, 1), strings.Replace(good, `"9000"`, `"16000"`, 1), strings.Replace(good, `"9000"`, `9000`, 1), strings.Replace(good, `"schema":1`, `"schema":2`, 1), strings.Replace(good, `"9000"`, `"9000","mode":"x"`, 1), good + `{}`, strings.Repeat(" ", 1025) + good} {
		if _, err := decodeLocalMacMTUCapPreference([]byte(body), sid); err == nil {
			t.Fatal("invalid preference accepted", body)
		}
	}
	if _, err := localMacMTUCapPreferenceName(`..\outside`); err == nil {
		t.Fatal("invalid owner accepted")
	}
}
