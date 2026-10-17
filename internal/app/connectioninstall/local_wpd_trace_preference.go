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

// Trace preference records intent only; the active debug master and native
// ETW session ownership checks separately gate collection.
type localWPDTracePreference struct {
	Schema   int    `json:"schema"`
	OwnerSID string `json:"owner_sid"`
	Enabled  *bool  `json:"enabled"`
}

func localWPDTracePreferenceName(sid string) (string, error) {
	if !validPreparedUserSID(sid) {
		return "", fmt.Errorf("LOCAL_WPD_TRACE_OWNER_INVALID")
	}
	sum := sha256.Sum256([]byte(sid))
	return "local-wpd-trace-preference-" + hex.EncodeToString(sum[:]) + ".json", nil
}

func decodeLocalWPDTracePreference(b []byte, sid string) (bool, error) {
	if _, err := localWPDTracePreferenceName(sid); err != nil {
		return false, err
	}
	if len(b) > 1024 {
		return false, fmt.Errorf("LOCAL_WPD_TRACE_PREFERENCE_INVALID")
	}
	var p localWPDTracePreference
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Schema != 1 || p.OwnerSID != sid || p.Enabled == nil {
		return false, fmt.Errorf("LOCAL_WPD_TRACE_PREFERENCE_INVALID")
	}
	return *p.Enabled, nil
}
