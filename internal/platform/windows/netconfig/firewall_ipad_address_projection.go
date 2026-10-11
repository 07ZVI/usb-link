package netconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
)

// This DTO is an observation of four compiled selectors, never rule contents,
// Ready, compatibility, ownership, deletion or mutation authorization.
type IPadAddressShape struct {
	Kind          string `json:"kind"`
	Count         int    `json:"count"`
	IsAny         bool   `json:"is_any"`
	ExpectedExact bool   `json:"expected_exact"`
}
type IPadAddressProjection struct {
	Status         string           `json:"status"`
	RuleCount      int              `json:"rule_count"`
	FilterCount    int              `json:"filter_count"`
	MarkersMatch   bool             `json:"markers_match"`
	ProgramMatch   bool             `json:"program_match"`
	InterfaceMatch bool             `json:"interface_match"`
	Local          IPadAddressShape `json:"local"`
	Remote         IPadAddressShape `json:"remote"`
}
type IPadAddressProjectionRow struct {
	SelectorIndex int                   `json:"selector_index"`
	Public        IPadAddressProjection `json:"public"`
	Native        IPadAddressProjection `json:"native"`
}
type IPadAddressProjectionReport struct {
	DurationMS uint32                     `json:"duration_ms"`
	Schema     int                        `json:"schema"`
	ReadOnly   bool                       `json:"read_only"`
	Scope      string                     `json:"scope"`
	Status     string                     `json:"status"`
	Rows       []IPadAddressProjectionRow `json:"rows"`
}

const ipadAddressScope = "FIXED_CORE_IPAD_ADDRESS_OBSERVATION_NOT_OWNERSHIP_OR_NULL_COMPATIBILITY"
const IPadAddressProjectionPrefix = "USB_IPAD_ADDRESS_PROJECTION "

func ipadAddressUnread() IPadAddressProjection {
	return IPadAddressProjection{Status: "unavailable", Local: IPadAddressShape{Kind: "unread"}, Remote: IPadAddressShape{Kind: "unread"}}
}
func ipadAddressReport() IPadAddressProjectionReport {
	v := IPadAddressProjectionReport{Schema: 1, ReadOnly: true, Scope: ipadAddressScope, Status: "unavailable", Rows: []IPadAddressProjectionRow{}}
	for i := 0; i < 4; i++ {
		v.Rows = append(v.Rows, IPadAddressProjectionRow{SelectorIndex: i, Public: ipadAddressUnread(), Native: ipadAddressUnread()})
	}
	return v
}
func ipadAddressShape(values []string, kind, expected string) IPadAddressShape {
	out := IPadAddressShape{Kind: kind}
	if kind != "string" && kind != "array" {
		return out
	}
	if len(values) > 64 {
		return IPadAddressShape{Kind: "other"}
	}
	for _, s := range values {
		if len(s) > 1024 || strings.ContainsRune(s, 0) {
			return IPadAddressShape{Kind: "other"}
		}
	}
	out.Count = len(values)
	out.IsAny = len(values) == 1 && strings.EqualFold(values[0], "Any")
	got := append([]string{}, values...)
	want := strings.Split(expected, ",")
	slices.Sort(got)
	slices.Sort(want)
	out.ExpectedExact = slices.Equal(got, want)
	return out
}
func IPadAddressProjectionValid(v *IPadAddressProjectionReport) bool {
	if v == nil || v.DurationMS > 12000 || v.Schema != 1 || !v.ReadOnly || v.Scope != ipadAddressScope || len(v.Rows) != 4 || !projectionEnum(v.Status, "unavailable", "observed", "partly_unavailable", "scope_changed") {
		return false
	}
	for i, r := range v.Rows {
		if r.SelectorIndex != i {
			return false
		}
		for _, p := range []IPadAddressProjection{r.Public, r.Native} {
			if !projectionEnum(p.Status, "unavailable", "rule_absent", "rule_not_unique", "filter_not_unique", "observed") || p.RuleCount < 0 || p.RuleCount > 2 || p.FilterCount < 0 || p.FilterCount > 2 {
				return false
			}
			if p.Status == "observed" && (p.RuleCount != 1 || p.FilterCount != 1) {
				return false
			}
			for _, s := range []IPadAddressShape{p.Local, p.Remote} {
				if !projectionEnum(s.Kind, "unread", "missing", "empty", "null", "string", "array", "other") || s.Count < 0 || s.Count > 64 {
					return false
				}
				if s.Kind != "string" && s.Kind != "array" && (s.Count != 0 || s.IsAny || s.ExpectedExact) {
					return false
				}
				if s.Kind == "string" && s.Count != 1 {
					return false
				}
				if s.IsAny && s.Count != 1 {
					return false
				}
				if (s.IsAny || s.ExpectedExact) && p.Status != "observed" {
					return false
				}
			}
		}
	}
	return true
}
func DecodeIPadAddressProjection(b []byte) (*IPadAddressProjectionReport, error) {
	bad := errors.New("IPAD_ADDRESS_PROJECTION_INVALID")
	if len(b) == 0 || len(b) > 8192 {
		return nil, bad
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if residentJSONUnique(d) != nil || d.Decode(new(any)) != io.EOF || !projectionExactObject(b, reflect.TypeOf(IPadAddressProjectionReport{})) {
		return nil, bad
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(b, &root)
	var rows []json.RawMessage
	if json.Unmarshal(root["rows"], &rows) != nil || len(rows) != 4 {
		return nil, bad
	}
	for _, r := range rows {
		if !projectionExactObject(r, reflect.TypeOf(IPadAddressProjectionRow{})) {
			return nil, bad
		}
		var row map[string]json.RawMessage
		_ = json.Unmarshal(r, &row)
		for _, key := range []string{"public", "native"} {
			if !projectionExactObject(row[key], reflect.TypeOf(IPadAddressProjection{})) {
				return nil, bad
			}
			var p map[string]json.RawMessage
			_ = json.Unmarshal(row[key], &p)
			for _, key := range []string{"local", "remote"} {
				if !projectionExactObject(p[key], reflect.TypeOf(IPadAddressShape{})) {
					return nil, bad
				}
			}
		}
	}
	var v IPadAddressProjectionReport
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || !IPadAddressProjectionValid(&v) {
		return nil, bad
	}
	return &v, nil
}
