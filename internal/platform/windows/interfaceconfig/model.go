// Package interfaceconfig owns only explicitly selected interface optimizations.
// Saved GUIDs are recovery obligations, never live-device authorization.
package interfaceconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
)

const HostGUID = "{C839CF3F-7F98-4CB3-891B-36E4FC772969}"
const MacGUID = "{A4611646-E050-4D25-B83E-633A5598F302}"

type Scope struct {
	Role  string `json:"role"`
	GUID  string `json:"guid"`
	Index uint32 `json:"index"`
	LUID  uint64 `json:"luid"`
}
type Observation struct {
	Kind       string `json:"kind"`
	Applied    bool   `json:"applied"`
	Verified   bool   `json:"verified"`
	DurationMS int64  `json:"duration_ms"`
	Code       string `json:"code"`
}
type dadOriginal struct {
	Scope    Scope  `json:"scope"`
	Original uint32 `json:"original"`
}
type persistentOriginal struct {
	Scope          Scope            `json:"scope"`
	OriginalMTU    uint32           `json:"original_mtu"`
	DesiredMTU     uint32           `json:"desired_mtu"`
	AddressAbsent  bool             `json:"address_absent"`
	Address        string           `json:"address"`
	Prefix         uint32           `json:"prefix"`
	Profile        *profileOriginal `json:"profile,omitempty"`
	AppliedAddress *addressBaseline `json:"applied_address,omitempty"`
}
type addressBaseline struct {
	ValidLifetime     string `json:"valid_lifetime"`
	PreferredLifetime string `json:"preferred_lifetime"`
}
type profileOriginal struct {
	NetworkGUID string `json:"network_guid"`
	Category    int32  `json:"category"`
}
type configReceipt struct {
	Version          int                  `json:"version"`
	RestoreRequested bool                 `json:"restore_requested,omitempty"`
	DAD              []dadOriginal        `json:"dad"`
	Persistent       []persistentOriginal `json:"persistent"`
}

var guidPattern = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}$`)

func validateScope(s Scope) error {
	if s.Index == 0 || s.LUID == 0 || !guidPattern.MatchString(s.GUID) {
		return errors.New("USB_INTERFACE_CONFIG_SCOPE_INVALID")
	}
	switch s.Role {
	case "host":
		if !strings.EqualFold(s.GUID, HostGUID) {
			return errors.New("USB_INTERFACE_CONFIG_SCOPE_INVALID")
		}
	case "mac":
		if !strings.EqualFold(s.GUID, MacGUID) {
			return errors.New("USB_INTERFACE_CONFIG_SCOPE_INVALID")
		}
	case "ipad":
	default:
		return errors.New("USB_INTERFACE_CONFIG_SCOPE_INVALID")
	}
	return nil
}
func decodeConfigReceipt(b []byte) (configReceipt, error) {
	var v configReceipt
	fail := func() (configReceipt, error) { return v, errors.New("USB_INTERFACE_CONFIG_RECEIPT_INVALID") }
	if len(b) == 0 || len(b) > 16384 || !uniqueJSON(b) || !requiredReceiptFields(b) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || v.Version != 1 || len(v.DAD) > 16 || len(v.Persistent) > 16 {
		return fail()
	}
	seen := map[string]bool{}
	for _, r := range v.DAD {
		if validateScope(r.Scope) != nil || r.Original > 32 || seen[strings.ToUpper(r.Scope.GUID)] {
			return fail()
		}
		seen[strings.ToUpper(r.Scope.GUID)] = true
	}
	seen = map[string]bool{}
	for _, r := range v.Persistent {
		if validateScope(r.Scope) != nil || r.OriginalMTU < 576 || r.OriginalMTU > 65535 || r.DesiredMTU != 1500 || !r.AddressAbsent || r.Address != scopeAddress(r.Scope) || r.Prefix != 32 || seen[strings.ToUpper(r.Scope.GUID)] {
			return fail()
		}
		if r.Profile != nil && (!guidPattern.MatchString(r.Profile.NetworkGUID) || r.Profile.Category < 0 || r.Profile.Category > 1) {
			return fail()
		}
		if r.AppliedAddress != nil && (r.AppliedAddress.ValidLifetime == "" || r.AppliedAddress.PreferredLifetime == "" || len(r.AppliedAddress.ValidLifetime) > 64 || len(r.AppliedAddress.PreferredLifetime) > 64) {
			return fail()
		}
		seen[strings.ToUpper(r.Scope.GUID)] = true
	}
	return v, nil
}
func uniqueJSON(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	var read func() bool
	read = func() bool {
		t, e := d.Token()
		if e != nil {
			return false
		}
		c, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch c {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return false
				}
				seen[s] = true
				if !read() {
					return false
				}
			}
			t, e = d.Token()
			return e == nil && t == json.Delim('}')
		case '[':
			for d.More() {
				if !read() {
					return false
				}
			}
			t, e = d.Token()
			return e == nil && t == json.Delim(']')
		}
		return false
	}
	return read() && d.Decode(new(any)) == io.EOF
}
func sameConfigReceipt(a, b configReceipt) bool { return reflect.DeepEqual(a, b) }

// An update may append obligations or remove verified obligations, but may
// never rewrite the original value for a still-owned interface.
func sameConfigBaselines(a, b configReceipt) bool {
	for _, x := range a.DAD {
		for _, y := range b.DAD {
			if strings.EqualFold(x.Scope.GUID, y.Scope.GUID) && x != y {
				return false
			}
		}
	}
	for _, x := range a.Persistent {
		for _, y := range b.Persistent {
			if strings.EqualFold(x.Scope.GUID, y.Scope.GUID) {
				check := y
				if x.AppliedAddress == nil {
					check.AppliedAddress = nil
				}
				if x.Profile == nil {
					check.Profile = nil
				}
				if !reflect.DeepEqual(x, check) {
					return false
				}
			}
		}
	}
	return a.Version == b.Version && (!a.RestoreRequested || b.RestoreRequested)
}

func requiredReceiptFields(b []byte) bool {
	var v struct {
		Version *int `json:"version"`
		DAD     []struct {
			Original *uint32 `json:"original"`
		} `json:"dad"`
		Persistent []struct {
			OriginalMTU *uint32 `json:"original_mtu"`
			DesiredMTU  *uint32 `json:"desired_mtu"`
			Absent      *bool   `json:"address_absent"`
			Prefix      *uint32 `json:"prefix"`
			Profile     *struct {
				Category *int32 `json:"category"`
			} `json:"profile"`
		} `json:"persistent"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return false
	}
	if raw, ok := fields["restore_requested"]; ok {
		var flag *bool
		if json.Unmarshal(raw, &flag) != nil || flag == nil {
			return false
		}
	}
	if json.Unmarshal(b, &v) != nil || v.Version == nil {
		return false
	}
	for _, x := range v.DAD {
		if x.Original == nil {
			return false
		}
	}
	for _, x := range v.Persistent {
		if x.OriginalMTU == nil || x.DesiredMTU == nil || x.Absent == nil || x.Prefix == nil || (x.Profile != nil && x.Profile.Category == nil) {
			return false
		}
	}
	return true
}

// Each role has one product-owned secondary/source address. The instance GUID
// remains independently authorized by fresh native proof; an address is not identity.
func scopeAddress(s Scope) string {
	switch s.Role {
	case "host":
		return "10.6.9.1"
	case "mac":
		return "10.6.9.253"
	case "ipad":
		return "10.6.9.254"
	}
	return ""
}
func scopeSkip(s Scope) bool { return s.Role != "host" }
