package netconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

const MacNullProjectionPrefix = "USB_MAC_NULL_PROJECTION "

// These bounded shapes contain no rule values, paths or identifiers. They are
// observations only and never authorize repair, NULL equivalence or readiness.
type MacNullProjectionRow struct {
	SelectorIndex      int    `json:"selector_index"`
	Status             string `json:"status"`
	Phase              string `json:"phase"`
	PublicRuleCount    int    `json:"public_rule_count"`
	PublicFilterCount  int    `json:"public_filter_count"`
	CIMRuleCount       int    `json:"cim_rule_count"`
	CIMFilterCount     int    `json:"cim_filter_count"`
	PublicProgramKind  string `json:"public_program_kind"`
	PublicProgramIsAny bool   `json:"public_program_is_any"`
	CIMAppPathKind     string `json:"cim_app_path_kind"`
	CIMAppPathIsAny    bool   `json:"cim_app_path_is_any"`
}
type MacNullProjection struct {
	Schema   int                    `json:"schema"`
	ReadOnly bool                   `json:"read_only"`
	Rows     []MacNullProjectionRow `json:"rows"`
}

func projectionEnum(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
func MacNullProjectionValid(v *MacNullProjection) bool {
	if v == nil || v.Schema != 1 || !v.ReadOnly || len(v.Rows) != 5 {
		return false
	}
	for i, r := range v.Rows {
		if r.SelectorIndex != i || !projectionEnum(r.Status, "unavailable", "rule_absent", "rule_not_unique", "filter_not_unique", "observed") || !projectionEnum(r.Phase, "public_rule", "public_filter", "cim_rule", "cim_filter") {
			return false
		}
		for _, n := range []int{r.PublicRuleCount, r.PublicFilterCount, r.CIMRuleCount, r.CIMFilterCount} {
			if n < 0 || n > 2 {
				return false
			}
		}
		for _, k := range []string{r.PublicProgramKind, r.CIMAppPathKind} {
			if !projectionEnum(k, "unread", "missing", "null", "string", "other") {
				return false
			}
		}
		if (r.PublicProgramIsAny && r.PublicProgramKind != "string") || (r.CIMAppPathIsAny && r.CIMAppPathKind != "string") {
			return false
		}
	}
	return true
}
func CopyMacNullProjection(v *MacNullProjection) *MacNullProjection {
	if !MacNullProjectionValid(v) {
		return nil
	}
	out := *v
	out.Rows = append([]MacNullProjectionRow(nil), v.Rows...)
	return &out
}

// Require every compiled JSON field, including false/zero fields, and reject
// unknown, duplicate, null and trailing values before decoding the typed DTO.
func projectionExactObject(b []byte, typ reflect.Type) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != typ.NumField() {
		return false
	}
	for i := 0; i < typ.NumField(); i++ {
		raw, ok := fields[typ.Field(i).Tag.Get("json")]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	return true
}
func DecodeMacNullProjection(b []byte) (*MacNullProjection, error) {
	bad := errors.New("MAC_NULL_PROJECTION_INVALID")
	if len(b) == 0 || len(b) > 4096 {
		return nil, bad
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if residentJSONUnique(d) != nil || d.Decode(new(any)) != io.EOF || !projectionExactObject(b, reflect.TypeOf(MacNullProjection{})) {
		return nil, bad
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(b, &root)
	var rows []json.RawMessage
	if json.Unmarshal(root["rows"], &rows) != nil || len(rows) != 5 {
		return nil, bad
	}
	for _, r := range rows {
		if !projectionExactObject(r, reflect.TypeOf(MacNullProjectionRow{})) {
			return nil, bad
		}
	}
	var v MacNullProjection
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || !MacNullProjectionValid(&v) {
		return nil, bad
	}
	return &v, nil
}
