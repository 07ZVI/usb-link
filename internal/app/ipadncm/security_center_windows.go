//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
	"suhang/usbnet/internal/security/appfirewall"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/security/deviceguard"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/security/usbgateway"
	"sync"
	"time"
)

type desktopRequest struct {
	Action        string `json:"action"`
	Password      string `json:"password,omitempty"`
	Username      string `json:"username,omitempty"`
	Remember      bool   `json:"remember,omitempty"`
	ID            string `json:"id,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	AccountAccess string `json:"account_access,omitempty"`
	GuestAccess   string `json:"guest_access,omitempty"`
	Path          string `json:"path,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Direction     string `json:"direction,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Remote        string `json:"remote,omitempty"`
	Port          uint16 `json:"port,omitempty"`
}

var applicationFirewall struct {
	sync.Mutex
	manager *appfirewall.Manager
}

func appFirewall(ctx context.Context) (*appfirewall.Manager, error) {
	applicationFirewall.Lock()
	defer applicationFirewall.Unlock()
	if applicationFirewall.manager != nil {
		return applicationFirewall.manager, nil
	}
	dir, err := connectioninstall.SecurityDirectory()
	if err != nil {
		return nil, err
	}
	m, err := appfirewall.New(ctx, appfirewall.DiskStore{Dir: dir}, appfirewall.WindowsExecutor{})
	if err == nil {
		applicationFirewall.manager = m
	}
	return m, err
}

func RemoveApplicationFirewall(ctx context.Context) error {
	m, err := appFirewall(ctx)
	if err != nil {
		return err
	}
	if err = m.RemoveAll(ctx); err != nil {
		return err
	}
	dir, err := connectioninstall.SecurityDirectory()
	if err != nil {
		return err
	}
	if err = usbgateway.RemoveAll(dir); err != nil {
		return err
	}
	if netconfig.NativeNetworkEnabled() {
		if err := netconfig.RemoveCoreServicesNative(ctx, nil); err != nil {
			return err
		}
		return (appfirewall.DiskStore{Dir: dir}).RemoveEmpty()
	}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return e
	}
	output, problem := runApplicationScript(filepath.Clean(system), netconfig.RemoveCoreServicesRules())
	if problem != "" || output != "USB_CORE_PERMISSION_REMOVED" {
		return fmt.Errorf("USB core permission cleanup failed: %s", problem)
	}
	return (appfirewall.DiskStore{Dir: dir}).RemoveEmpty()
}

var securityCenterBusy sync.Mutex

func securityDesktopAction(action string) bool {
	switch action {
	case "security-refresh", "firewall-upsert", "firewall-delete", "firewall-discard-pending":
		return true
	}
	return false
}
func desktopRequestResultEvent(action string) string {
	if securityDesktopAction(action) {
		return "security"
	}
	if gatewayDesktopAction(action) {
		return "gateway"
	}
	return "share-folders"
}

func (u *modernUI) securityAction(v desktopRequest) bool {
	if !securityDesktopAction(v.Action) {
		return false
	}
	if !securityCenterBusy.TryLock() {
		u.setNotice("正在處理安全設定，請稍候。")
		u.sendEvent(map[string]any{"event": "security", "action": v.Action, "request_id": v.RequestID, "problem": "SECURITY_OPERATION_BUSY：正在處理其他安全設定，請稍後重新整理。"})
		return true
	}
	go func() {
		defer securityCenterBusy.Unlock()
		ctx, cancel := context.WithTimeout(u.lifetime, 45*time.Second)
		defer cancel()
		m, err := appFirewall(ctx)
		if err == nil {
			switch v.Action {
			case "firewall-upsert":
				err = m.Upsert(ctx, appfirewall.Rule{ID: v.ID, Application: appfirewall.Identity{Path: v.Path}, Action: v.Decision, Direction: v.Direction, Protocol: v.Protocol, Remote: v.Remote, Port: v.Port})
			case "firewall-delete":
				err = m.Delete(ctx, v.ID)
			case "firewall-discard-pending":
				err = m.DiscardPending(ctx)
			}
		}
		problem := ""
		rules := []appfirewall.Rule{}
		if m != nil {
			if ae := m.Audit(ctx); ae != nil && err == nil {
				err = ae
			}
			rules, problem = m.Snapshot()
		}
		if err != nil {
			problem = err.Error()
			u.setNotice("安全設定未完成：" + problem)
		} else if v.Action != "security-refresh" {
			u.setNotice("Windows 應用程式規則已更新；不改變全機預設聯網方式。")
		}
		connections, ce := appfirewall.Connections(ctx)
		if ce != nil {
			connections = []appfirewall.Connection{}
			problem += fmt.Sprintf("\nTCP：%v", ce)
		}
		nodes, ne := deviceguard.Inventory(ctx)
		devices, de := deviceguard.USBList(nodes, ne == nil)
		if de != nil {
			devices = []securitypolicy.DeviceRecord{}
			problem += fmt.Sprintf("\nUSB：%v", de)
		} else {
			deviceguard.MarkConnectionDevice(devices, macconnection.CurrentRoot(), "Mac")
			enrichUSBConnections(ctx, nodes, devices)
			deviceguard.EnrichStorage(ctx, devices)
		}
		u.sendEvent(securityUIMessage(v.Action, v.RequestID, rules, connections, devices, problem, securitySummary()))
	}()
	return true
}
