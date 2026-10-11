package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func ValidateResidentSession(v OwnedSession) error {
	if v.Version != ResidentSessionVersion || v.GUID != retainedMacGUID || !retainedToken.MatchString(v.Token) || v.Retained != nil || (v.Status != "ACTIVE" && v.Status != "CLEAN" && v.Status != "CLEANUP_REQUIRED") {
		return errors.New("MAC_RESIDENT_SESSION_INVALID")
	}
	return nil
}

func ParseResidentSession(b []byte) (OwnedSession, error) {
	var v OwnedSession
	if len(b) == 0 || len(b) > 4096 || !uniqueSessionJSON(b) {
		return v, errors.New("MAC_RESIDENT_SESSION_INVALID")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != 4 {
		return v, errors.New("MAC_RESIDENT_SESSION_INVALID")
	}
	for _, key := range []string{"version", "guid", "token", "status"} {
		if _, ok := fields[key]; !ok {
			return v, errors.New("MAC_RESIDENT_SESSION_INVALID")
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return v, errors.New("MAC_RESIDENT_SESSION_INVALID")
	}
	return v, ValidateResidentSession(v)
}

// Drift detection for this caller's held current lease only. Recovery uses
// complete adapter absence, never this journal as new removal authority.
func VerifyLiveResidentSession(expected, observed OwnedSession) error {
	if ValidateResidentSession(expected) != nil || ValidateResidentSession(observed) != nil || expected.Status != "ACTIVE" || observed != expected {
		return errors.New("MAC_RESIDENT_LIVE_SESSION_CHANGED")
	}
	return nil
}
