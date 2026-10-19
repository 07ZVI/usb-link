//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalPhotoPreferenceOwnerAndIndependentSchema(t *testing.T) {
	sid, other := "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	name, err := localPhotoPreferenceName(sid)
	if err != nil {
		t.Fatal(err)
	}
	master, _ := localDebugPreferenceName(sid)
	foreign, _ := localPhotoPreferenceName(other)
	if name == master || name == foreign || strings.Contains(name, sid) {
		t.Fatal("preference namespace or owner collision")
	}
	for _, enabled := range []bool{false, true} {
		b, _ := json.Marshal(localPhotoPreference{Schema: 1, OwnerSID: sid, Enabled: &enabled})
		got, e := decodeLocalPhotoPreference(b, sid)
		if e != nil || got != enabled {
			t.Fatal(got, e)
		}
		if _, e := decodeLocalPhotoPreference(b, other); e == nil {
			t.Fatal("foreign owner accepted")
		}
	}
}

func TestLocalPhotoPreferenceRejectsIncompleteOrForeignData(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	good := `{"schema":1,"owner_sid":"` + sid + `","enabled":true}`
	for _, body := range []string{`{}`, strings.Replace(good, `,"enabled":true`, "", 1), strings.Replace(good, `true`, `null`, 1), strings.Replace(good, `true`, `"true"`, 1), strings.Replace(good, `"schema":1`, `"schema":2`, 1), strings.Replace(good, `true`, `true,"mode":"fast"`, 1), good + `{}`, strings.Repeat(" ", 1025) + good} {
		if _, err := decodeLocalPhotoPreference([]byte(body), sid); err == nil {
			t.Fatal("invalid preference accepted", body)
		}
	}
	if _, err := localPhotoPreferenceName(`..\outside`); err == nil {
		t.Fatal("invalid owner accepted")
	}
}
