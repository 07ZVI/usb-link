//go:build usblink_local_remote

package connectioninstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

type localTimingPreference struct {
	Schema   int    `json:"schema"`
	OwnerSID string `json:"owner_sid"`
	Mode     string `json:"mode"`
}

func validLocalTimingMode(mode string) bool {
	return mode == "normal" || mode == "fast" || mode == "delayed"
}
func localTimingPreferenceName(sid string) (string, error) {
	if !validPreparedUserSID(sid) {
		return "", fmt.Errorf("LOCAL_TIMING_OWNER_INVALID")
	}
	sum := sha256.Sum256([]byte(sid))
	return "local-timing-preference-" + hex.EncodeToString(sum[:]) + ".json", nil
}
func decodeLocalTimingPreference(b []byte, sid string) (string, error) {
	if _, err := localTimingPreferenceName(sid); err != nil {
		return "normal", err
	}
	if len(b) > 1024 {
		return "normal", fmt.Errorf("LOCAL_TIMING_PREFERENCE_INVALID")
	}
	var p localTimingPreference
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Schema != 1 || p.OwnerSID != sid || !validLocalTimingMode(p.Mode) {
		return "normal", fmt.Errorf("LOCAL_TIMING_PREFERENCE_INVALID")
	}
	return p.Mode, nil
}
