package interfaceconfig

import (
	"strings"
	"testing"
)

func TestMacTimingReceiptContainsOnlyBoundedMeasurementScalars(t *testing.T) {
	good := `[{"role":"mac","kind":"dad_apply","calls":2,"failures":1,"disabled":0,"duration_ms":9}]`
	if r, e := DecodeMacObservations([]byte(good)); e != nil || len(r) != 1 || r[0].DurationMS != 9 {
		t.Fatal(r, e)
	}
	if _, e := DecodeMacObservations([]byte(`[]`)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{`null`, good + `{}`, strings.Replace(good, `"role":"mac"`, `"role":"host"`, 1), strings.Replace(good, `"kind":"dad_apply"`, `"kind":"device_path"`, 1), strings.Replace(good, `"calls":2`, `"calls":2,"calls":3`, 1), strings.Replace(good, `"calls":2`, `"calls":null`, 1), strings.Replace(good, `"calls":2`, `"calls":0`, 1), strings.Replace(good, `"failures":1`, `"failures":3`, 1), strings.Replace(good, `"duration_ms":9`, `"duration_ms":-1`, 1), strings.Replace(good, `"duration_ms":9`, `"duration_ms":9,"path":"secret"`, 1), "[" + strings.Repeat(strings.Trim(good, "[]")+",", 5) + strings.Trim(good, "[]") + "]"} {
		if _, e := DecodeMacObservations([]byte(bad)); e == nil {
			t.Fatal("unbounded/identity-bearing measurement accepted")
		}
	}
}
