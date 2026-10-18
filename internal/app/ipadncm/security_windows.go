//go:build windows && amd64

package ipadncm

import (
	"context"
	"suhang/usbnet/internal/security/deviceguard"
	"suhang/usbnet/internal/security/hostsecurity"
	"suhang/usbnet/internal/security/securitypolicy"
	"sync"
	"time"
)

var securityStatus = struct {
	sync.Mutex
	USB  securitypolicy.DeviceVerdict
	Host securitypolicy.Evidence
}{Host: securitypolicy.Evidence{State: securitypolicy.Unknown, Code: "HOST_FIREWALL_UNAVAILABLE", Scope: "host"}}

func queryHostSecurity(ctx context.Context) {
	e := hostsecurity.QueryFirewall(ctx)
	securityStatus.Lock()
	securityStatus.Host = e
	securityStatus.Unlock()
}

func securitySummary() string {
	securityStatus.Lock()
	defer securityStatus.Unlock()
	firewall := "系統防火牆狀態未確認"
	if securityStatus.Host.State == securitypolicy.Verified {
		firewall = "系統防火牆設定已核對"
	}
	if securityStatus.Host.State == securitypolicy.Degraded {
		firewall = "系統防火牆未完整啟用"
	}
	usb := "USB 輸入介面尚未檢查"
	if securityStatus.USB.Admit {
		usb = "USB 未發現 HID 介面"
	}
	if securityStatus.USB.Code == "USB_UNEXPECTED_HID_INTERFACE" {
		usb = "USB 出現 HID，已拒絕網路連線"
	}
	return firewall + " · " + usb + "；全機 HID 安裝攔截尚未啟用"
}

// Each attempt has its own cancellation scope. Security refusal must stop only
// that attempt, leave the UI resident and never consume automatic retry budget.
func (a *ConnectionAuthorization) BeginSecurityAttempt(ctx context.Context, cancel context.CancelFunc) {
	a.guardContext, a.guardCancel = ctx, cancel
	a.transientFailure, a.lastFreshTransient, a.promptShown = false, false, false
	recordAuthorizationOutcome(authorizationOutcome{})
	a.securityMu.Lock()
	a.securityFailure = ""
	a.Security = securitypolicy.DeviceVerdict{}
	a.securityMu.Unlock()
	securityStatus.Lock()
	securityStatus.USB = securitypolicy.DeviceVerdict{}
	securityStatus.Unlock()
}

func (a *ConnectionAuthorization) checkSecurity(root string) bool {
	ctx := a.guardContext
	if ctx == nil {
		ctx = connectionContext()
	}
	v := deviceguard.CheckUSB(ctx, root)
	a.securityMu.Lock()
	a.Security = v
	if !v.Admit {
		a.securityFailure = v.Code
	}
	a.securityMu.Unlock()
	securityStatus.Lock()
	securityStatus.USB = v
	securityStatus.Unlock()
	if !v.Admit {
		a.ConsentStatus = v.Code
		a.transientFailure = false
		if a.guardCancel != nil {
			a.guardCancel()
		}
	}
	return v.Admit
}

func (a *ConnectionAuthorization) watchSecurity(root string) {
	if a.guardStop != nil || a.guardContext == nil || a.guardCancel == nil {
		return
	}
	ctx, cancel := context.WithCancel(a.guardContext)
	done := make(chan struct{})
	a.guardStop = func() { cancel(); <-done }
	go func() {
		defer close(done)
		var last securitypolicy.DeviceVerdict
		report := func(v securitypolicy.DeviceVerdict) {
			last = v
			a.securityMu.Lock()
			if a.securityFailure == "" {
				a.Security = v
			} // Read after joining.
			v = a.Security
			a.securityMu.Unlock()
			securityStatus.Lock()
			securityStatus.USB = v
			securityStatus.Unlock()
		}
		stop := func() {
			a.securityMu.Lock()
			if a.securityFailure == "" {
				a.securityFailure = last.Code
				a.Security = last
			}
			a.securityMu.Unlock()
			a.guardCancel()
		}
		events, unsubscribe, e := deviceguard.SubscribeChanges()
		if e != nil {
			deviceguard.Watch(ctx, root, 2*time.Second, deviceguard.CheckUSB, report, stop)
			return
		}
		defer unsubscribe()
		deviceguard.WatchChanges(ctx, root, events, 2*time.Second, deviceguard.CheckUSB, report, stop)
	}()
}

func (a *ConnectionAuthorization) FinishSecurityAttempt() {
	if a.guardStop != nil {
		a.guardStop()
		a.guardStop = nil
	}
	a.guardContext, a.guardCancel = nil, nil
	securityStatus.Lock()
	a.HostFirewall = securityStatus.Host
	securityStatus.Unlock()
}

func (a *ConnectionAuthorization) SecurityFailure() string {
	a.securityMu.Lock()
	defer a.securityMu.Unlock()
	return a.securityFailure
}

func DeviceWatchDetails() any { return deviceguard.ChangeDiagnostics() }

func MeasurementGuardBaseline(seconds int) { deviceguard.SetPollingBaseline(seconds) }
