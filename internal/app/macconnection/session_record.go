package macconnection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/bridge"
)

type sessionRecord = bridge.OwnedSession

func parseSessionRecord(b []byte) (sessionRecord, error) {
	var r sessionRecord
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if len(b) > 8192 || decoder.Decode(&r) != nil {
		return r, fmt.Errorf("owned record invalid")
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		return r, fmt.Errorf("owned record invalid")
	}
	switch r.Version {
	case "0.4.1-phase02", "0.6.1-phase02", "0.6.2-phase02", bridge.SessionVersion:
	case bridge.RetainedSessionVersion:
		if _, e := bridge.ParseRetainedSession(b); e != nil {
			return r, e
		}
	case bridge.ResidentSessionVersion:
		if _, e := bridge.ParseResidentSession(b); e != nil {
			return r, e
		}
	case "0.8.15-independent-out": // Exact broken release tag: permit owned recovery only.
	default:
		return r, fmt.Errorf("owned record invalid")
	}
	if r.Version != bridge.RetainedSessionVersion && r.Retained != nil {
		return r, fmt.Errorf("owned retained record invalid")
	}
	if r.Status != "ACTIVE" && r.Status != "CLEAN" && r.Status != "CLEANUP_REQUIRED" {
		return r, fmt.Errorf("owned record invalid")
	}
	if _, err := netconfig.VerifyCleanup(r.GUID, r.Token); err != nil {
		return r, err
	}
	return r, nil
}

// RemoteReady requires the listener used for USB upgrade discovery as well as
// the resolved USB peer. A working bridge alone cannot acknowledge an upgrade.
func RemoteReady(peerResolved, receiverReady bool, fileError string) bool {
	return peerResolved && receiverReady && fileError == ""
}
