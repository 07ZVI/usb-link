package netconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func anchorProjectionFixture() *MacAnchorProjection {
	v := &MacAnchorProjection{Schema: 1, ReadOnly: true}
	for i := 0; i < 5; i++ {
		r := MacAnchorProjectionRow{SelectorIndex: i, Status: "observed", PublicRuleCount: 1, CIMRuleCount: 1, Fields: []MacAnchorProjectionField{}}
		for _, key := range residentAnchors {
			class, field, _ := strings.Cut(key, "/")
			if class == "" {
				class = firewallRuleDiagnosticClass
			}
			r.Fields = append(r.Fields, MacAnchorProjectionField{Field: class + "/" + field, PublicCount: 1, CIMCount: 1, PublicKind: "string", CIMKind: "string", PublicIsExactExpected: true, CIMIsExactExpected: true})
		}
		v.Rows = append(v.Rows, r)
	}
	return v
}

func TestMacAnchorProjectionStrictDecoderAndDeepCopy(t *testing.T) {
	v := anchorProjectionFixture()
	b, _ := json.Marshal(v)
	parsed, e := DecodeMacAnchorProjection(b)
	if e != nil || parsed == nil {
		t.Fatal(e)
	}
	copy := CopyMacAnchorProjection(parsed)
	copy.Rows[0].Fields[0].Field = "private/path"
	if parsed.Rows[0].Fields[0].Field == "private/path" {
		t.Fatal("copy aliases fields")
	}
	for _, bad := range []string{
		strings.Replace(string(b), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(string(b), `"schema":1`, `"schema":1,"arbitrary":"private"`, 1),
		strings.Replace(string(b), `"read_only":true`, `"read_only":null`, 1),
		strings.Replace(string(b), `"public_is_exact_expected":true`, `"public_is_exact_expected":null`, 1),
		strings.Replace(string(b), `"public_count":1,`, ``, 1),
		strings.Replace(string(b), `"field":"MSFT_NetFirewallRule/InstanceID"`, `"field":"arbitrary/private"`, 1),
		string(b) + `{}`,
		strings.Repeat(" ", MacAnchorProjectionByteLimit+1),
	} {
		if _, e := DecodeMacAnchorProjection([]byte(bad)); e == nil {
			t.Fatal("ambiguous/unbounded/foreign JSON accepted")
		}
	}
}

func TestMacAnchorProjectionRejectsContradictoryCountsAndShapes(t *testing.T) {
	mutations := []func(*MacAnchorProjection){
		func(v *MacAnchorProjection) { v.Schema = 2 },
		func(v *MacAnchorProjection) { v.ReadOnly = false },
		func(v *MacAnchorProjection) { v.Rows = v.Rows[:4] },
		func(v *MacAnchorProjection) { v.Rows[0].SelectorIndex = 1 },
		func(v *MacAnchorProjection) { v.Rows[0].Status = "private/raw" },
		func(v *MacAnchorProjection) { v.Rows[0].Fields = v.Rows[0].Fields[:3] },
		func(v *MacAnchorProjection) { v.Rows[0].Fields[1] = v.Rows[0].Fields[0] },
		func(v *MacAnchorProjection) { v.Rows[0].Fields[0].PublicKind = "NULL_IS_ANY" },
		func(v *MacAnchorProjection) { v.Rows[0].Fields[0].CIMKind = "unsigned_integer" },
		func(v *MacAnchorProjection) { v.Rows[0].Fields[0].CIMKind = "null" },
		func(v *MacAnchorProjection) { v.Rows[0].Fields[0].PublicCount = 2 },
		func(v *MacAnchorProjection) { v.Rows[0].Fields[0].CIMCount = 3 },
		func(v *MacAnchorProjection) { v.Rows[0].Fields[0].PublicIsKnown8AnyCode = true },
		func(v *MacAnchorProjection) { v.Rows[0].PublicRuleCount = 2 },
		func(v *MacAnchorProjection) { v.Rows[0].Status = "rule_absent" },
		func(v *MacAnchorProjection) { v.Rows[0].Status = "unavailable" },
	}
	for i, change := range mutations {
		v := anchorProjectionFixture()
		change(v)
		if MacAnchorProjectionValid(v) || CopyMacAnchorProjection(v) != nil {
			t.Fatal("invalid shape", i)
		}
	}
	// A real nonunique filter is representable only as unread/no-match/no-shape.
	v := anchorProjectionFixture()
	v.Rows[0].Status = "filter_not_unique"
	f := &v.Rows[0].Fields[0]
	f.PublicCount = 2
	f.PublicKind = "unread"
	f.PublicIsExactExpected = false
	if !MacAnchorProjectionValid(v) {
		t.Fatal("bounded ambiguous observation refused")
	}
	// A present NULL never reports an exact match. ICMP literal shape is only
	// allowed on selector 0's specific IcmpType field, and is not Ready evidence.
	v = anchorProjectionFixture()
	for j := range v.Rows[0].Fields {
		f := &v.Rows[0].Fields[j]
		if f.Field == "MSFT_NetProtocolPortFilter/IcmpType" {
			f.PublicKind, f.CIMKind = "string_array", "string_array"
			f.PublicIsKnown8AnyCode, f.CIMIsKnown8AnyCode = true, true
		}
	}
	if !MacAnchorProjectionValid(v) {
		t.Fatal("fixed ICMP literal observation")
	}
	v.Rows[1].Fields[len(v.Rows[1].Fields)-1].PublicKind = "string_array"
	v.Rows[1].Fields[len(v.Rows[1].Fields)-1].PublicIsKnown8AnyCode = true
	if MacAnchorProjectionValid(v) {
		t.Fatal("ICMP observation enabled for TCP selector")
	}
}

func TestMacAnchorProjectionNumericProtocolIsReadOnlyAndFieldLimited(t *testing.T) {
	v := anchorProjectionFixture()
	for i := range v.Rows {
		for j := range v.Rows[i].Fields {
			if v.Rows[i].Fields[j].Field == "MSFT_NetProtocolPortFilter/Protocol" {
				v.Rows[i].Fields[j].CIMKind = "unsigned_integer"
			}
		}
	}
	if !MacAnchorProjectionValid(v) {
		t.Fatal("bounded protocol projection")
	}
	s := ResidentMacAnchorProjectionScript()
	if !strings.Contains(s, "$field -eq 'Protocol' -and $v -is [uint16] -and $v -le 255") {
		t.Fatal("numeric diagnostic not exact uint16 protocol")
	}
}

func TestMacAnchorProjectionAbsentAndUnavailableFixedRows(t *testing.T) {
	v := anchorProjectionFixture()
	for i := 3; i < 5; i++ {
		v.Rows[i] = MacAnchorProjectionRow{SelectorIndex: i, Status: "rule_absent", Fields: []MacAnchorProjectionField{}}
	}
	v.Rows[2] = MacAnchorProjectionRow{SelectorIndex: 2, Status: "unavailable", Fields: []MacAnchorProjectionField{}}
	b, _ := json.Marshal(v)
	if _, e := DecodeMacAnchorProjection(b); e != nil {
		t.Fatal(e)
	}
}
