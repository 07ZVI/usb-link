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

// Service-hold preference records intent only; the active debug master and native
// service ownership checks separately gate collection.
type localAMDSHoldPreference struct {
	Schema   int    `json:"schema"`
	OwnerSID string `json:"owner_sid"`
	Enabled  *bool  `json:"enabled"`
}

func localAMDSHoldPreferenceName(sid string) (string, error) {
	if !validPreparedUserSID(sid) {
		return "", fmt.Errorf("LOCAL_AMDS_HOLD_OWNER_INVALID")
	}
	sum := sha256.Sum256([]byte(sid))
	return "local-amds-hold-preference-" + hex.EncodeToString(sum[:]) + ".json", nil
}

func decodeLocalAMDSHoldPreference(b []byte, sid string) (bool, error) {
	if _, err := localAMDSHoldPreferenceName(sid); err != nil {
		return false, err
	}
	if len(b) > 1024 {
		return false, fmt.Errorf("LOCAL_AMDS_HOLD_PREFERENCE_INVALID")
	}
	var p localAMDSHoldPreference
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Schema != 1 || p.OwnerSID != sid || p.Enabled == nil {
		return false, fmt.Errorf("LOCAL_AMDS_HOLD_PREFERENCE_INVALID")
	}
	return *p.Enabled, nil
}
