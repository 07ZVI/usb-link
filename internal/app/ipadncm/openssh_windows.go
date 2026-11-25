//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"suhang/usbnet/internal/security/openssh"
)

var opensshBusy sync.Mutex

func (u *modernUI) opensshAction(v desktopRequest) bool {
	if !opensshDesktopAction(v.Action) {
		return false
	}
	reply := func(s *openssh.Status, err error) {
		m := map[string]any{"event": "openssh", "action": v.Action, "request_id": v.RequestID}
		if s != nil {
			m["status"] = s
		}
		if err != nil {
			m["problem"] = err.Error()
		}
		u.sendEvent(m)
	}
	if !validStartupDisplayRequestID(v.RequestID) {
		reply(nil, fmt.Errorf("OpenSSH 請求識別碼無效。"))
		return true
	}
	if len(v.Username) > 184 || v.Password != "" || v.Upstream != 0 || v.Remember || v.AccountAccess != "" || v.GuestAccess != "" || v.Decision != "" || v.Direction != "" || v.Protocol != "" || v.Remote != "" || v.Port != 0 ||
		(v.PublicKey != "" && v.Action != "openssh-import") || (v.ID != "" && v.Action != "openssh-delete") || (v.Path != "" && v.Action != "openssh-install-offline") ||
		(v.Action == "openssh-import" && (v.Username == "" || len(v.PublicKey) == 0 || len(v.PublicKey) > openssh.MaxImport)) ||
		(v.Action == "openssh-delete" && (v.Username == "" || len(v.ID) != 64)) ||
		(v.Action == "openssh-install-offline" && (!filepath.IsAbs(v.Path) || len(v.Path) > 1024)) {
		reply(nil, fmt.Errorf("OpenSSH 請求內容無效，請重新整理後再試。"))
		return true
	}
	if !opensshBusy.TryLock() {
		reply(nil, fmt.Errorf("正在處理 OpenSSH，請稍後重新整理。"))
		return true
	}
	go func() {
		defer opensshBusy.Unlock()
		ctx, cancel := context.WithTimeout(u.lifetime, 10*time.Minute)
		defer cancel()
		var s openssh.Status
		var err error
		switch v.Action {
		case "openssh-import":
			s, err = openssh.ChangeKeys(ctx, v.Username, v.PublicKey, "")
		case "openssh-delete":
			s, err = openssh.ChangeKeys(ctx, v.Username, "", v.ID)
		case "openssh-install-offline":
			err = openssh.InstallPackage(ctx, v.Path)
		case "openssh-install-download":
			err = openssh.InstallPackage(ctx, "")
		default:
			action := v.Action[len("openssh-"):]
			sid := v.Username
			if action != "refresh" {
				sid = ""
			}
			s, err = openssh.Query(ctx, action, sid)
		}
		if err != nil {
			// A failed command is not evidence of unchanged state. Read again;
			// leave the UI's last known snapshot intact if readback also fails.
			readCtx, readCancel := context.WithTimeout(u.lifetime, 20*time.Second)
			defer readCancel()
			if actual, e := openssh.Query(readCtx, "refresh", ""); e == nil {
				reply(&actual, err)
			} else {
				reply(nil, err)
			}
			return
		}
		if v.Action != "openssh-refresh" && v.Action != "openssh-import" && v.Action != "openssh-delete" {
			s, err = openssh.Query(ctx, "refresh", v.Username)
		}
		if err != nil {
			readCtx, readCancel := context.WithTimeout(u.lifetime, 20*time.Second)
			defer readCancel()
			if actual, e := openssh.Query(readCtx, "refresh", ""); e == nil {
				reply(&actual, err)
			} else {
				reply(nil, err)
			}
		} else {
			reply(&s, nil)
		}
	}()
	return true
}
