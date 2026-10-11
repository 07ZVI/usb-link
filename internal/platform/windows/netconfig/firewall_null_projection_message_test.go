package netconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func projectionFixture() MacNullProjection {
	v := MacNullProjection{Schema: 1, ReadOnly: true}
	for i := 0; i < 5; i++ {
		v.Rows = append(v.Rows, MacNullProjectionRow{SelectorIndex: i, Status: "observed", Phase: "cim_filter", PublicRuleCount: 1, PublicFilterCount: 1, CIMRuleCount: 1, CIMFilterCount: 1, PublicProgramKind: "string", PublicProgramIsAny: true, CIMAppPathKind: "null"})
	}
	return v
}
func TestMacNullProjectionStrictShapeAndCopy(t *testing.T) {
	v := projectionFixture()
	b, _ := json.Marshal(v)
	out, e := DecodeMacNullProjection(b)
	if e != nil {
		t.Fatal(e)
	}
	copy := CopyMacNullProjection(out)
	copy.Rows[0].Status = "unavailable"
	if out.Rows[0].Status != "observed" {
		t.Fatal("aliased")
	}
	for _, bad := range []string{
		string(b) + "{}",
		strings.Replace(string(b), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(string(b), `"schema":1`, `"schema":1,"extra":0`, 1),
		strings.Replace(string(b), `"read_only":true`, `"read_only":null`, 1),
		strings.Replace(string(b), `"read_only":true`, `"read_only":false`, 1),
		strings.Replace(string(b), `"selector_index":1`, `"selector_index":0`, 1),
		strings.Replace(string(b), `"status":"observed"`, `"status":"foreign"`, 1),
		strings.Replace(string(b), `"public_rule_count":1`, `"public_rule_count":3`, 1),
		strings.Replace(string(b), `"cim_app_path_is_any":false`, `"cim_app_path_is_any":true`, 1),
		strings.Replace(string(b), `"public_program_kind":"string"`, `"public_program_kind":null`, 1),
		strings.Replace(string(b), `"public_program_is_any":true,`, "", 1),
		strings.Replace(string(b), `"public_program_is_any":true`, `"public_program_is_any":true,"public_program_is_any":false`, 1),
		strings.Replace(string(b), `"phase":"cim_filter"`, `"phase":"cim_filter","path":"private"`, 1),
		strings.Repeat(" ", 4097),
	} {
		if _, e := DecodeMacNullProjection([]byte(bad)); e == nil {
			t.Fatalf("bad accepted %s", bad)
		}
	}
	row := []byte(`{"operation":"diagnostic","count":1,"duration_ms":20,"success":true}`)
	if r, e := DecodeBridgeNetworkScriptTiming(row); e != nil || r.Operation != "diagnostic" {
		t.Fatal(r, e)
	}
}
