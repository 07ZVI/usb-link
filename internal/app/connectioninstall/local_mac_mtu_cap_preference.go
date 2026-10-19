//go:build usblink_local_remote

package connectioninstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"suhang/usbnet/internal/transport/ncm"
)

// The Mac MTU cap preference records developer-experiment intent only. It is
// honoured solely while the developer master switch is on and applies to the
// next Mac connection.
type localMacMTUCapPreference struct {
	Schema   int    `json:"schema"`
	OwnerSID string `json:"owner_sid"`
	Cap      string `json:"cap"`
}

func localMacMTUCapPreferenceName(sid string) (string, error) {
	if !validPreparedUserSID(sid) {
		return "", fmt.Errorf("LOCAL_MAC_MTU_CAP_OWNER_INVALID")
	}
	sum := sha256.Sum256([]byte(sid))
	return "local-mac-mtu-cap-preference-" + hex.EncodeToString(sum[:]) + ".json", nil
}

func decodeLocalMacMTUCapPreference(b []byte, sid string) (string, error) {
	if _, err := localMacMTUCapPreferenceName(sid); err != nil {
		return "", err
	}
	if len(b) > 1024 {
		return "", fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_INVALID")
	}
	var p localMacMTUCapPreference
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Schema != 1 || p.OwnerSID != sid || p.Cap == "" {
		return "", fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_INVALID")
	}
	cap, err := ncm.ParseMTUCap(p.Cap)
	if err != nil {
		return "", fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_INVALID")
	}
	return cap.String(), nil
}
