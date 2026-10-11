package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

var retainedToken = regexp.MustCompile(`^[a-f0-9]{24}$`)
var retainedSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

const retainedMacGUID = "{A4611646-E050-4D25-B83E-633A5598F302}"

func ValidateRetainedSession(v OwnedSession) error {
	if v.Version != RetainedSessionVersion || v.GUID != retainedMacGUID || !retainedToken.MatchString(v.Token) || (v.Status != "ACTIVE" && v.Status != "CLEAN" && v.Status != "CLEANUP_REQUIRED") || v.Retained == nil {
		return errors.New("MAC_RETAINED_SESSION_INVALID")
	}
	r := v.Retained
	if r.Index == 0 || r.LUID == 0 || r.Created <= 0 || (r.Mode != "legacy" && r.Mode != "persistent") || !retainedSHA.MatchString(r.ReceiptSHA256) {
		return errors.New("MAC_RETAINED_SESSION_INVALID")
	}
	return nil
}
func ParseRetainedSession(b []byte) (OwnedSession, error) {
	var v OwnedSession
	if len(b) == 0 || len(b) > 4096 || !uniqueSessionJSON(b) {
		return v, errors.New("MAC_RETAINED_SESSION_INVALID")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != 5 {
		return v, errors.New("MAC_RETAINED_SESSION_INVALID")
	}
	var r map[string]json.RawMessage
	if json.Unmarshal(fields["retained_address"], &r) != nil || len(r) != 6 {
		return v, errors.New("MAC_RETAINED_SESSION_INVALID")
	}
	for _, key := range []string{"version", "guid", "token", "status", "retained_address"} {
		if _, ok := fields[key]; !ok {
			return v, errors.New("MAC_RETAINED_SESSION_INVALID")
		}
	}
	for _, key := range []string{"index", "luid", "created", "mode", "receipt_sha256", "network_prepared"} {
		if _, ok := r[key]; !ok {
			return v, errors.New("MAC_RETAINED_SESSION_INVALID")
		}
	}
	var prepared *bool
	if json.Unmarshal(r["network_prepared"], &prepared) != nil || prepared == nil {
		return v, errors.New("MAC_RETAINED_SESSION_INVALID")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return v, errors.New("MAC_RETAINED_SESSION_INVALID")
	}
	return v, ValidateRetainedSession(v)
}
func uniqueSessionJSON(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 8 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || seen[s] {
						return false
					}
					seen[s] = true
					if !walk(depth + 1) {
						return false
					}
				}
				t, e = d.Token()
				return e == nil && t == json.Delim('}')
			case '[':
				return false
			default:
				return false
			}
		}
		return true
	}
	return walk(0) && d.Decode(new(any)) == io.EOF
}
