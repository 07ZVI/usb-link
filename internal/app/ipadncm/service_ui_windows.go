//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/uistartup"
	"sync"
	"time"
)

type PanelRelay func(context.Context, string, string, string, []PanelCheck) (bool, []bool)

var panelRelay struct {
	sync.RWMutex
	fn PanelRelay
}

// SetPanelRelay routes service prompts to the authenticated local owner UI.
// No default yes, permission or device grant is manufactured by this hook.
func SetPanelRelay(fn PanelRelay) {
	panelRelay.Lock()
	panelRelay.fn = fn
	panelRelay.Unlock()
}
func currentPanelRelay() PanelRelay {
	panelRelay.RLock()
	defer panelRelay.RUnlock()
	return panelRelay.fn
}

var serviceDesktop struct {
	sync.Mutex
	u *modernUI
}

func serviceDesktopOwner(ctx context.Context) (*modernUI, error) {
	serviceDesktop.Lock()
	defer serviceDesktop.Unlock()
	if connectionMonitor() == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("CORE_MONITOR_INITIALIZING")
	}
	if serviceDesktop.u == nil {
		serviceDesktop.u = &modernUI{ctx: ctx, lifetime: ctx, state: &applicationState{selected: selectedDeviceMonitor, Settings: ShowConnectionSettings}, cancel: func() {}, messages: make(chan any, 64), serviceOwner: true}
		serviceDesktop.u.watchGateway()
	}
	return serviceDesktop.u, nil
}

// ServiceDesktopSnapshot is called only after local IPC token/source checks.
// It uses the same projection as the interactive product, never a second core.
func ServiceDesktopSnapshot(ctx context.Context) (json.RawMessage, error) {
	u, err := serviceDesktopOwner(ctx)
	if err != nil {
		return nil, err
	}
	var events []any
	for len(events) < 8 {
		select {
		case v := <-u.messages:
			events = append(events, v)
		default:
			goto drained
		}
	}
drained:
	b, err := json.Marshal(ServiceDisplaySnapshot{Desktop: u.desktopStatus(), Connections: ServiceMonitorResults(), Events: events})
	if err != nil || len(b) > 48<<10 {
		return nil, fmt.Errorf("CORE_DESKTOP_STATUS_TOO_LARGE")
	}
	return b, nil
}

func ServiceMonitorResults() map[string]ApplicationResult {
	out := make(map[string]ApplicationResult)
	for _, device := range []string{"Mac", "iPad"} {
		if s := deviceMonitor(device); s != nil {
			out[device] = s.snapshot()
		}
	}
	return out
}

// ApplyServiceMonitorResults only updates the login UI's displayed state.
// It is never used by the service to establish authority or readiness.
func ApplyServiceMonitorResults(results map[string]ApplicationResult) {
	for _, device := range []string{"Mac", "iPad"} {
		r, ok := results[device]
		if !ok || r.DeviceKind != device {
			continue
		}
		if s := deviceMonitor(device); s != nil {
			s.Lock()
			s.r = r
			s.Unlock()
		}
	}
}

// ServiceDesktopAction retains all existing per-action validators. The pipe
// layer must require the bound owner, elevated token and verified UI image.
func ServiceDesktopAction(ctx context.Context, payload json.RawMessage) error {
	if len(payload) == 0 || len(payload) > 32768 {
		return fmt.Errorf("CORE_ACTION_INVALID")
	}
	var request desktopRequest
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("CORE_ACTION_INVALID")
	}
	if request.Action == "smb-ui-result-ack" || request.Action == "ui-result-ack" {
		return acknowledgeSMBUIResult(request)
	}
	if request.RequestID != "" && !validStartupDisplayRequestID(request.RequestID) {
		return fmt.Errorf("CORE_ACTION_INVALID")
	}
	switch request.Action {
	case "select-mac", "select-ipad", "share-on", "share-off", "ipad-revoke-trust", "startup-on", "startup-off", "retry", "retry-mac", "retry-ipad", "benchmark-start", "benchmark-cancel", "security-refresh", "firewall-upsert", "firewall-delete", "firewall-discard-pending", "settings":
	default:
		if !serviceAdditionalAction(request.Action) {
			return fmt.Errorf("CORE_ACTION_UNSUPPORTED")
		}
	}
	if request.RequestID != "" {
		connectioninstall.RecordSMBUIResult(request.RequestID, request.Action, "core-received")
	} else if strings.HasPrefix(request.Action, "native-smb-") {
		connectioninstall.RecordSMBUIResult(request.ID, request.Action, "core-received")
	}
	u, err := serviceDesktopOwner(ctx)
	if err != nil {
		return err
	}
	if !u.shareFoldersAction(request) && !u.gatewayAction(request) && !u.securityAction(request) {
		if request.Action == "startup-on" || request.Action == "startup-off" {
			u.startupAction(request.Action, request.ID)
		} else {
			u.action(request.Action)
		}
	}
	return nil
}

// An account read replies on the requesting pipe. It must not depend on an
// unrelated shared-folder refresh or a later, destructively drained snapshot.
func ServiceSMBAccountRead(ctx context.Context, payload json.RawMessage) (json.RawMessage, bool, error) {
	var request desktopRequest
	if json.Unmarshal(payload, &request) != nil || request.Action != "native-smb-account-read" {
		return nil, false, nil
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
		return nil, true, fmt.Errorf("CORE_ACCOUNT_READ_INVALID")
	}
	if ctx.Err() != nil {
		return nil, true, ctx.Err()
	}
	if request.RequestID != "" || request.AccountAccess != "" || request.GuestAccess != "" || request.Password != "" || request.Username != "" || request.Path != "" || request.Decision != "" || request.Direction != "" || request.Protocol != "" || request.Remote != "" || request.Port != 0 || request.ID != "" && !validStartupDisplayRequestID(request.ID) {
		return nil, true, fmt.Errorf("CORE_ACCOUNT_READ_INVALID")
	}
	connectioninstall.RecordSMBUIResult(request.ID, request.Action, "core-received")
	account := connectioninstall.ReadNativeSMBAccount(request.Remember)
	b, err := json.Marshal(map[string]any{"event": "smb-account", "action": request.Action, "request_id": request.ID, "account": account, "guest": connectioninstall.NativeSMBGuestEnabled()})
	connectioninstall.RecordSMBUIResult(request.ID, request.Action, "reply-ready")
	return b, true, err
}

func serviceAdditionalAction(action string) bool {
	// Exact existing command names only; no shell/SCM/filename endpoint.
	switch action {
	case "share-folders-refresh", "share-folder-add", "share-folder-remove", "native-smb-access-save", "native-smb-acl-forget", "native-smb-release", "native-smb-account-read", "native-smb-account-save", "native-smb-account-create", "native-smb-account-reset", "native-smb-account-rename", "native-smb-guest-on", "native-smb-guest-off", "native-smb-repair", "native-smb-retry", "gateway-refresh", "gateway-decide", "gateway-forget":
		return true
	}
	return false
}

type ServiceDisplaySnapshot struct {
	Desktop     any                          `json:"desktop"`
	Connections map[string]ApplicationResult `json:"connections"`
	Events      []any                        `json:"events,omitempty"`
}

// UI replays pending gateway requests on opening. A lost display message
// never approves a request: the authoritative pending record stays in core.
func ServiceReplayDesktopRequests(ctx context.Context) error {
	u, err := serviceDesktopOwner(ctx)
	if err == nil {
		u.replayGatewayRequests()
	}
	return err
}

func (u *modernUI) proxyAction(v desktopRequest) bool {
	p := currentServiceUIProxy()
	if p == nil {
		return false
	}
	switch v.Action {
	case "open-share", "share-folder-open", "windows-smb-manage", "stop":
		if !u.shareFoldersAction(v) {
			u.action(v.Action)
		}
	default:
		b, err := json.Marshal(v)
		if err == nil {
			go func() {
				reply, err := p.Action(u.lifetime, b)
				if err != nil {
					u.setNotice("CORE_UI_ACTION_FAILED: " + err.Error())
					if v.RequestID != "" {
						u.sendEvent(map[string]any{"event": desktopRequestResultEvent(v.Action), "action": v.Action, "request_id": v.RequestID, "problem": err.Error()})
					}
					if strings.HasPrefix(v.Action, "native-smb-") && v.RequestID == "" {
						u.sendEvent(map[string]any{"event": "smb-account", "action": v.Action, "request_id": v.ID, "problem": err.Error()})
					}
				} else if len(reply) > 0 && string(reply) != "{}" {
					deadline := time.Now().Add(55 * time.Second)
					for {
						var pending struct {
							Event       string `json:"event"`
							ID          string `json:"request_id"`
							ResultEvent string `json:"result_event"`
						}
						if json.Unmarshal(reply, &pending) != nil || pending.Event != "smb-result-pending" {
							break
						}
						if time.Now().After(deadline) {
							break
						}
						select {
						case <-u.lifetime.Done():
							return
						case <-time.After(time.Second):
						}
						query, _ := json.Marshal(desktopRequest{Action: "ui-result-read", ID: pending.ID, Decision: pending.ResultEvent})
						reply, err = p.Action(u.lifetime, query)
						if err != nil {
							reply, _ = json.Marshal(map[string]any{"event": pending.ResultEvent, "request_id": pending.ID, "action": v.Action, "problem": err.Error()})
							break
						}
					}
					u.sendEvent(reply)
				}
			}()
		}
	}
	return true
}

func (u *modernUI) proxyPush(p *ServiceUIProxy) {
	b, err := p.Read(u.lifetime)
	if err != nil {
		u.setNotice("CORE_UI_WAITING: " + err.Error())
		return
	}
	var snapshot struct {
		Desktop     json.RawMessage              `json:"desktop"`
		Connections map[string]ApplicationResult `json:"connections"`
		Events      []json.RawMessage            `json:"events"`
	}
	if json.Unmarshal(b, &snapshot) != nil || len(snapshot.Desktop) == 0 {
		return
	}
	ApplyServiceMonitorResults(snapshot.Connections)
	u.publishStatus(snapshot.Desktop)
	for _, event := range snapshot.Events {
		u.sendEvent(event)
	}
}

type ServiceUIProxy struct {
	ObserveOpen func(uistartup.Timing)
	Read        func(context.Context) (json.RawMessage, error)
	Action      func(context.Context, json.RawMessage) (json.RawMessage, error)
}

var serviceUIProxy struct {
	sync.RWMutex
	proxy *ServiceUIProxy
}

func SetServiceUIProxy(proxy *ServiceUIProxy) {
	serviceUIProxy.Lock()
	serviceUIProxy.proxy = proxy
	serviceUIProxy.Unlock()
}
func currentServiceUIProxy() *ServiceUIProxy {
	serviceUIProxy.RLock()
	defer serviceUIProxy.RUnlock()
	return serviceUIProxy.proxy
}

func recordDesktopOpenTiming(request, stage string, started time.Time) {
	p := currentServiceUIProxy()
	if p == nil || p.ObserveOpen == nil {
		return
	}
	p.ObserveOpen(uistartup.Timing{Request: request, Stage: stage, ElapsedUS: uint64(max(1, time.Since(started).Microseconds()))})
}
