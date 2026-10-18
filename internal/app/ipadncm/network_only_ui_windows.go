//go:build windows && amd64

package ipadncm

func (u *modernUI) networkOnlyAction(a, id string) {
	if a != "network-only-on" && a != "network-only-off" || id != "" && !validStartupDisplayRequestID(id) {
		return
	}
	u.mu.Lock()
	if u.networkOnlyBusy || u.ctx.Err() != nil {
		u.networkOnlyRejectedID = id
		u.mu.Unlock()
		u.push()
		return
	}
	u.networkOnlyBusy, u.networkOnlyRequested, u.networkOnlyRequestID = true, a == "network-only-on", id
	u.notice = "正在儲存「僅保留網路連線」設定…"
	u.mu.Unlock()
	u.push()
	go func() {
		e := setNetworkOnlySwitch(a == "network-only-on")
		u.mu.Lock()
		u.networkOnlyBusy = false
		switch {
		case e != nil:
			u.notice = "「僅保留網路連線」設定未儲存：" + e.Error()
		case a == "network-only-on":
			u.notice = "「僅保留網路連線」已開啟；已記住的 iPad 照片介面會先行封鎖。"
		default:
			u.notice = "「僅保留網路連線」已關閉，正在還原；以下狀態顯示還原結果。"
		}
		u.mu.Unlock()
		u.push()
	}()
}

func isNetworkOnlyAction(a string) bool { return a == "network-only-on" || a == "network-only-off" }

// Caller holds u.mu.
func (u *modernUI) networkOnlyIsolationStatusLocked() networkOnlyIsolationStatus {
	s := networkOnlyFromPhoto(networkOnlySwitchOn(), localPhoto.snapshot())
	s.Busy, s.Requested, s.RequestID, s.RejectedID = u.networkOnlyBusy, u.networkOnlyRequested, u.networkOnlyRequestID, u.networkOnlyRejectedID
	return s
}
