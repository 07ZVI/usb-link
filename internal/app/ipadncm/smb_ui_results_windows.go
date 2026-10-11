//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"suhang/usbnet/internal/app/connectioninstall"
	"time"
)

// Local, bounded, short-lived results. A snapshot never consumes SMB results;
// only the matching renderer acknowledgement does. Password reveals use the
// direct reply and are never retained here.
var smbUIResults desktopUIResultCache

func retainSMBUIResult(message any) bool {
	m, ok := message.(map[string]any)
	if !ok {
		return false
	}
	event, _ := m["event"].(string)
	id, _ := m["request_id"].(string)
	if !localUIResultEvent(event) || !validStartupDisplayRequestID(id) {
		return false
	}
	if account, ok := m["account"].(connectioninstall.SMBAccountView); ok && account.Password != "" {
		return false
	}
	action, _ := m["action"].(string)
	smbUIResults.put(event, id, action, message, time.Now())
	connectioninstall.RecordSMBUIResult(id, action, "reply-ready")
	return true
}
func getSMBUIResult(event, id string) json.RawMessage {
	if b := smbUIResults.get(event, id, time.Now()); len(b) > 0 {
		return b
	}
	b, _ := json.Marshal(map[string]any{"event": "smb-result-pending", "request_id": id, "result_event": event})
	return b
}
func acknowledgeSMBUIResult(v desktopRequest) error {
	if !validStartupDisplayRequestID(v.ID) || !localUIResultEvent(v.Decision) || v.Password != "" || v.Username != "" || v.Path != "" || v.RequestID != "" || v.AccountAccess != "" || v.GuestAccess != "" || v.Remember || v.Direction != "" || v.Protocol != "" || v.Port != 0 || v.Remote != "" {
		return fmt.Errorf("SMB_RESULT_ACK_INVALID")
	}
	smbUIResults.ack(v.Decision, v.ID)
	connectioninstall.RecordSMBUIResult(v.ID, "", "renderer-acknowledged")
	return nil
}
func PendingSMBUIReply(payload json.RawMessage) json.RawMessage {
	var v desktopRequest
	if json.Unmarshal(payload, &v) != nil {
		return nil
	}
	if securityDesktopAction(v.Action) || gatewayDesktopAction(v.Action) {
		if validStartupDisplayRequestID(v.RequestID) {
			event := "security"
			if gatewayDesktopAction(v.Action) {
				event = "gateway"
			}
			return getSMBUIResult(event, v.RequestID)
		}
		return nil
	}
	if v.RequestID != "" && validStartupDisplayRequestID(v.RequestID) {
		return getSMBUIResult("share-folders", v.RequestID)
	}
	switch v.Action {
	case "native-smb-account-save", "native-smb-account-create", "native-smb-account-reset", "native-smb-account-rename", "native-smb-guest-on", "native-smb-guest-off", "native-smb-retry", "native-smb-repair":
		if validStartupDisplayRequestID(v.ID) {
			return getSMBUIResult("smb-account", v.ID)
		}
	}
	return nil
}
func ServiceSMBDesktopRead(ctx context.Context, payload json.RawMessage) (json.RawMessage, bool, error) {
	var v desktopRequest
	if json.Unmarshal(payload, &v) != nil {
		return nil, false, nil
	}
	if v.Action == "native-smb-account-read" {
		return ServiceSMBAccountRead(ctx, payload)
	}
	if v.Action != "share-folders-refresh" && v.Action != "smb-ui-result-read" && v.Action != "ui-result-read" {
		return nil, false, nil
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || ctx.Err() != nil || v.Password != "" || v.Username != "" || v.Path != "" || v.Remember || v.AccountAccess != "" || v.GuestAccess != "" || v.Direction != "" || v.Remote != "" || v.Port != 0 || v.Protocol != "" {
		return nil, true, fmt.Errorf("SMB_RESULT_READ_INVALID")
	}
	if v.Action == "smb-ui-result-read" || v.Action == "ui-result-read" {
		if !validStartupDisplayRequestID(v.ID) || v.RequestID != "" || !localUIResultEvent(v.Decision) {
			return nil, true, fmt.Errorf("SMB_RESULT_READ_INVALID")
		}
		return getSMBUIResult(v.Decision, v.ID), true, nil
	}
	if !validStartupDisplayRequestID(v.RequestID) || v.ID != "" || v.Decision != "" {
		return nil, true, fmt.Errorf("SMB_FOLDER_READ_INVALID")
	}
	connectioninstall.RecordSMBUIResult(v.RequestID, v.Action, "core-received")
	done, accepted := smbUIResults.startRead(ctx, "share-folders", v.RequestID, v.Action, func() any {
		folders, err := connectioninstall.NativeSMBManagerFolders()
		problem := ""
		if err != nil {
			problem = err.Error()
		}
		connectioninstall.RecordSMBUIResult(v.RequestID, v.Action, "reply-ready")
		return map[string]any{"event": "share-folders", "action": v.Action, "request_id": v.RequestID, "folders": folders, "problem": problem}
	})
	if !accepted {
		return nil, true, fmt.Errorf("SMB_FOLDER_READ_BUSY：共享列表仍在讀取，請稍後重新整理。")
	}
	// Fast local reads retain their direct reply. Only a slow disk/ACL query
	// yields this pipe request instead of keeping it occupied for seconds.
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
		return nil, true, ctx.Err()
	case <-timer.C:
	}
	return getSMBUIResult("share-folders", v.RequestID), true, nil
}

func localUIResultEvent(event string) bool {
	return event == "smb-account" || event == "share-folders" || event == "security" || event == "gateway"
}
