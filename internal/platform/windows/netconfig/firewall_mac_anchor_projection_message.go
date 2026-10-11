package netconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

const MacAnchorProjectionPrefix = "USB_MAC_ANCHOR_PROJECTION "
const MacAnchorProjectionByteLimit = 32768

// Observation only: these booleans never authorize Ready or repair. The ICMP
// flag recognizes only literal 8 and 8:*; it is not a semantic equivalence gate.
type MacAnchorProjectionField struct {
	Field                 string `json:"field"`
	PublicCount           int    `json:"public_count"`
	CIMCount              int    `json:"cim_count"`
	PublicKind            string `json:"public_kind"`
	CIMKind               string `json:"cim_kind"`
	PublicIsExactExpected bool   `json:"public_is_exact_expected"`
	CIMIsExactExpected    bool   `json:"cim_is_exact_expected"`
	PublicIsKnown8AnyCode bool   `json:"public_is_known_8_any_code"`
	CIMIsKnown8AnyCode    bool   `json:"cim_is_known_8_any_code"`
}
type MacAnchorProjectionRow struct {
	SelectorIndex   int                        `json:"selector_index"`
	Status          string                     `json:"status"`
	PublicRuleCount int                        `json:"public_rule_count"`
	CIMRuleCount    int                        `json:"cim_rule_count"`
	Fields          []MacAnchorProjectionField `json:"fields"`
}
type MacAnchorProjection struct {
	Schema   int                      `json:"schema"`
	ReadOnly bool                     `json:"read_only"`
	Rows     []MacAnchorProjectionRow `json:"rows"`
}

func anchorProjectionEnum(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
func anchorProjectionCount(n int) bool { return n >= 0 && n <= 2 }
func anchorProjectionShape(count int, kind string, exact, known bool, allowICMP, allowProtocol bool) bool {
	if !anchorProjectionCount(count) || !anchorProjectionEnum(kind, "unread", "missing", "null", "string", "string_array", "unsigned_integer", "other") || (kind == "unsigned_integer" && !allowProtocol) {
		return false
	}
	if count != 1 {
		return kind == "unread" && !exact && !known
	}
	if kind == "unread" || (exact && kind != "string" && kind != "string_array" && kind != "unsigned_integer") {
		return false
	}
	return !known || (allowICMP && kind == "string_array")
}
func MacAnchorProjectionValid(v *MacAnchorProjection) bool {
	if v == nil || v.Schema != 1 || !v.ReadOnly || len(v.Rows) != 5 {
		return false
	}
	for i, r := range v.Rows {
		if r.SelectorIndex != i || !anchorProjectionCount(r.PublicRuleCount) || !anchorProjectionCount(r.CIMRuleCount) {
			return false
		}
		switch r.Status {
		case "unavailable", "rule_not_unique":
			if len(r.Fields) != 0 {
				return false
			}
		case "rule_absent":
			if r.PublicRuleCount != 0 || r.CIMRuleCount != 0 || len(r.Fields) != 0 {
				return false
			}
		case "observed", "filter_not_unique":
			if r.PublicRuleCount != 1 || r.CIMRuleCount != 1 || len(r.Fields) != len(residentAnchors) {
				return false
			}
			ambiguous := false
			for j, f := range r.Fields {
				class, property, _ := strings.Cut(residentAnchors[j], "/")
				if class == "" {
					class = firewallRuleDiagnosticClass
				}
				if f.Field != class+"/"+property {
					return false
				}
				icmp := i == 0 && f.Field == "MSFT_NetProtocolPortFilter/IcmpType"
				protocol := f.Field == "MSFT_NetProtocolPortFilter/Protocol"
				if !anchorProjectionShape(f.PublicCount, f.PublicKind, f.PublicIsExactExpected, f.PublicIsKnown8AnyCode, icmp, protocol) || !anchorProjectionShape(f.CIMCount, f.CIMKind, f.CIMIsExactExpected, f.CIMIsKnown8AnyCode, icmp, protocol) {
					return false
				}
				ambiguous = ambiguous || f.PublicCount != 1 || f.CIMCount != 1
			}
			if ambiguous != (r.Status == "filter_not_unique") {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func CopyMacAnchorProjection(v *MacAnchorProjection) *MacAnchorProjection {
	if !MacAnchorProjectionValid(v) {
		return nil
	}
	out := *v
	out.Rows = append([]MacAnchorProjectionRow(nil), v.Rows...)
	for i := range out.Rows {
		out.Rows[i].Fields = append([]MacAnchorProjectionField{}, v.Rows[i].Fields...)
	}
	return &out
}

func anchorProjectionExactObject(b []byte, typ reflect.Type) bool {
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
func DecodeMacAnchorProjection(b []byte) (*MacAnchorProjection, error) {
	bad := errors.New("MAC_ANCHOR_PROJECTION_INVALID")
	if len(b) == 0 || len(b) > MacAnchorProjectionByteLimit {
		return nil, bad
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if residentJSONUnique(d) != nil || d.Decode(new(any)) != io.EOF || !anchorProjectionExactObject(b, reflect.TypeOf(MacAnchorProjection{})) {
		return nil, bad
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(b, &root)
	var rows []json.RawMessage
	if json.Unmarshal(root["rows"], &rows) != nil || len(rows) != 5 {
		return nil, bad
	}
	for _, row := range rows {
		if !anchorProjectionExactObject(row, reflect.TypeOf(MacAnchorProjectionRow{})) {
			return nil, bad
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(row, &fields)
		var leaves []json.RawMessage
		if json.Unmarshal(fields["fields"], &leaves) != nil {
			return nil, bad
		}
		for _, leaf := range leaves {
			if !anchorProjectionExactObject(leaf, reflect.TypeOf(MacAnchorProjectionField{})) {
				return nil, bad
			}
		}
	}
	var v MacAnchorProjection
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || !MacAnchorProjectionValid(&v) {
		return nil, bad
	}
	return &v, nil
}
