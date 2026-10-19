package ipadncm

import (
	"encoding/hex"
	"suhang/usbnet/internal/buildinfo"
)

type localControlFailure struct {
	Event     string `json:"event"`
	Action    string `json:"action"`
	RequestID string `json:"request_id"`
	Code      string `json:"code"`
}

// A failed call does not prove whether core applied the request. Release only
// the matching UI wait and let later snapshots establish the actual state.
func localControlFailureEvent(action, id string) (localControlFailure, bool) {
	switch action {
	case "local-usb-update-on", "local-usb-update-off", "photo-isolation-on", "photo-isolation-off", "photo-policy-on", "photo-policy-off", "ncm-direct-on", "ncm-direct-off", "amds-hold-on", "amds-hold-off", "mac-mtu-cap-auto", "mac-mtu-cap-9000", "mac-mtu-cap-1500":
	default:
		return localControlFailure{}, false
	}
	if len(id) != 32 {
		return localControlFailure{}, false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return localControlFailure{}, false
	}
	return localControlFailure{"local-control-result", action, id, "CORE_UI_ACTION_FAILED"}, true
}

func serviceAdditionalAction(action string) bool {
	// Exact existing command names only; no shell/SCM/filename endpoint.
	switch action {
	case "local-usb-update-on", "local-usb-update-off":
		return buildinfo.LocalRemote
	case "photo-isolation-on", "photo-isolation-off", "photo-policy-on", "photo-policy-off", "ncm-direct-on", "ncm-direct-off", "amds-hold-on", "amds-hold-off", "mac-mtu-cap-auto", "mac-mtu-cap-9000", "mac-mtu-cap-1500":
		return buildinfo.LocalRemote && buildinfo.LocalDiagnostics == "true"
	case "share-folders-refresh", "share-folder-add", "share-folder-remove", "native-smb-access-save", "native-smb-acl-forget", "native-smb-release", "native-smb-account-read", "native-smb-account-save", "native-smb-account-create", "native-smb-account-reset", "native-smb-account-rename", "native-smb-guest-on", "native-smb-guest-off", "native-smb-repair", "native-smb-retry", "gateway-refresh", "gateway-decide", "gateway-forget":
		return true
	}
	return false
}
