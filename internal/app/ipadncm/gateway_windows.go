//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"os"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/security/usbgateway"
	"time"
)

func gatewayManager() (*usbgateway.Manager, error) {
	dir, e := connectioninstall.SecurityDirectory()
	if e != nil {
		return nil, e
	}
	return usbgateway.New(dir)
}
func attachUSBApplicationGate(luid uint64) (func() error, error) {
	m, e := gatewayManager()
	if e != nil {
		return nil, e
	}
	path, e := os.Executable()
	if e != nil {
		return nil, e
	}
	stop, e := m.AttachUSB(luid, "10.6.9.3", path)
	if e != nil {
		return stop, e
	}
	undo, e := m.RestrictIPadNetworkOnly(luid)
	if e != nil {
		if cleanup := stop(); cleanup != nil {
			return nil, fmt.Errorf("%w; gateway cleanup failed: %v", e, cleanup)
		}
		return nil, e
	}
	return func() error {
		if e := undo(); e != nil {
			return e
		}
		return stop()
	}, nil
}
func (u *modernUI) gatewayAction(v desktopRequest) bool {
	if !gatewayDesktopAction(v.Action) {
		return false
	}
	go func() {
		m, e := gatewayManager()
		if e == nil {
			switch v.Action {
			case "gateway-decide":
				e = m.Decide(v.ID, v.Decision, v.Remember)
			case "gateway-forget":
				e = m.Forget(v.Path)
			}
		}
		u.sendGateway(m, e, v)
	}()
	return true
}
func gatewayDesktopAction(action string) bool {
	switch action {
	case "gateway-refresh", "gateway-decide", "gateway-forget":
		return true
	}
	return false
}
func (u *modernUI) sendGateway(m *usbgateway.Manager, e error, v desktopRequest) {
	problem := ""
	grants := []usbgateway.Grant{}
	links := 0
	if m != nil {
		grants, problem, links = m.Snapshot()
	}
	if e != nil {
		problem = e.Error()
	}
	u.sendEvent(map[string]any{"event": "gateway", "action": v.Action, "request_id": v.RequestID, "grants": grants, "problem": problem, "active_links": links})
}
func (u *modernUI) watchGateway() {
	// Lazy engine construction occurs before USB configuration, not in this UI
	// loop. Failed preparation is an explicit connection error, never fail-open.
	u.gatewayWatcher.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-u.lifetime.Done():
					return
				case <-ticker.C:
					m := usbgateway.Current()
					if m == nil {
						continue
					}
					select {
					case r := <-m.Requests:
						u.sendEvent(map[string]any{"event": "gateway-request", "request": r})
					default:
					}
				}
			}
		}()
	})
}

func (u *modernUI) replayGatewayRequests() {
	if m := usbgateway.Current(); m != nil {
		for _, r := range m.PendingRequests() {
			u.sendEvent(map[string]any{"event": "gateway-request", "request": r})
		}
	}
}
