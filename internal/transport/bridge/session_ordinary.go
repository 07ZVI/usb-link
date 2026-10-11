package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// This fixed four-field record detects drift of an already held live lease.
// It is not evidence of adapter ownership, creation, or DIF_REMOVE permission.
func ValidateOrdinarySession(v OwnedSession) error {
	if v.Version != SessionVersion || v.GUID != retainedMacGUID || !retainedToken.MatchString(v.Token) || v.Retained != nil || (v.Status != "ACTIVE" && v.Status != "CLEAN" && v.Status != "CLEANUP_REQUIRED") {
		return errors.New("MAC_ORDINARY_SESSION_INVALID")
	}
	return nil
}

func ParseOrdinarySession(b []byte) (OwnedSession, error) {
	var v OwnedSession
	if len(b) == 0 || len(b) > 4096 || !uniqueSessionJSON(b) {
		return v, errors.New("MAC_ORDINARY_SESSION_INVALID")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != 4 {
		return v, errors.New("MAC_ORDINARY_SESSION_INVALID")
	}
	for _, key := range []string{"version", "guid", "token", "status"} {
		if _, ok := fields[key]; !ok {
			return v, errors.New("MAC_ORDINARY_SESSION_INVALID")
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return v, errors.New("MAC_ORDINARY_SESSION_INVALID")
	}
	return v, ValidateOrdinarySession(v)
}

// Only the caller's current ACTIVE ordinary session may authorize its existing
// live-lease cleanup check. Old clean/pending records cannot be adopted.
func VerifyLiveOrdinarySession(expected, observed OwnedSession) error {
	if ValidateOrdinarySession(expected) != nil || ValidateOrdinarySession(observed) != nil || expected.Status != "ACTIVE" || observed != expected {
		return errors.New("MAC_ORDINARY_LIVE_SESSION_CHANGED")
	}
	return nil
}
