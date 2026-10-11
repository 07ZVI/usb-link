//go:build windows && amd64

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/app/usbhost"
	"suhang/usbnet/internal/dependencies"
	"suhang/usbnet/internal/security/internet"
	"sync"
	"sync/atomic"
	"time"
)

type internetRuntime struct {
	manager *internet.Manager
	backend *internet.WindowsBackend
	cancel  context.CancelFunc
	mu      sync.Mutex
	problem string
}

var currentInternet atomic.Pointer[internetRuntime]

func startInternet(ctx context.Context) func() {
	dir, e := connectioninstall.DependencyDirectory()
	if e != nil {
		log.Printf("INTERNET_DIRECTORY_FAILED: %v", e)
		return func() {}
	}
	b := &internet.WindowsBackend{Directory: dir, Safe: connectioninstall.VerifyDependencyPath, Host: usbhost.Proof}
	run, cancel := context.WithCancel(ctx)
	rt := &internetRuntime{backend: b, cancel: cancel}
	rt.manager = internet.New(b, func() (string, uint32, uint64, bool) {
		p, ok := usbhost.Proof()
		root := macconnection.CurrentRoot()
		return root, p.Index, p.LUID, ok && root != "" && ipadncm.RemoteUSBConnectionHealthy()
	})
	recovery, stop := context.WithTimeout(run, 20*time.Second)
	if e = b.Recover(recovery); e != nil {
		rt.problem = e.Error()
		log.Printf("INTERNET_RECOVERY_FAILED: %v", e)
	}
	stop()
	currentInternet.Store(rt)
	go dependencies.Default.Refresh()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-run.Done():
				return
			case <-ticker.C:
				s := rt.manager.Snapshot()
				if s.Plan == nil {
					continue
				}
				check, cancel := context.WithTimeout(run, 5*time.Second)
				rt.manager.Observe(check, b.Observation())
				cancel()
				s = rt.manager.Snapshot()
				if s.Plan != nil && (s.State == "ready" || s.State == "waiting_client") {
					if e := b.Renew(*s.Plan); e != nil {
						_ = rt.manager.Disable(context.Background())
					}
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if e := rt.manager.Disable(cleanup); e != nil {
			log.Printf("INTERNET_EXIT_CLEANUP_FAILED: %v", e)
		}
		currentInternet.CompareAndSwap(rt, nil)
	}
}
func extendDesktopSnapshot(display json.RawMessage) json.RawMessage {
	var d map[string]json.RawMessage
	if json.Unmarshal(display, &d) != nil {
		return display
	}
	d["dependencies"], _ = json.Marshal(dependencies.Default.Snapshot())
	state := internet.Status{State: "off", Problem: "INTERNET_CORE_INITIALIZING"}
	if rt := currentInternet.Load(); rt != nil {
		state = rt.manager.Snapshot()
		state.Upstreams = rt.backend.Choices()
		rt.mu.Lock()
		if rt.problem != "" {
			state.State = "recovery_required"
			state.Problem = rt.problem
		}
		rt.mu.Unlock()
	}
	d["internet_sharing"], _ = json.Marshal(state)
	out, _ := json.Marshal(d)
	return out
}
func internetAction(ctx context.Context, payload json.RawMessage) (bool, error) {
	var head struct {
		Action string `json:"action"`
	}
	if json.Unmarshal(payload, &head) != nil {
		return false, nil
	}
	switch head.Action {
	case "internet-enable", "internet-disable", "internet-refresh", "dependency-refresh":
	default:
		return false, nil
	}
	var command struct {
		Action   string `json:"action"`
		Upstream uint32 `json:"upstream,omitempty"`
	}
	if e := strictCorePayload(payload, &command); e != nil {
		return true, e
	}
	if command.Action == "dependency-refresh" {
		dependencies.Default.Refresh()
		return true, nil
	}
	rt := currentInternet.Load()
	if rt == nil {
		return true, errors.New("INTERNET_INITIALIZING")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if head.Action == "internet-disable" {
		if rt.problem != "" {
			e := rt.backend.Recover(ctx)
			if e == nil {
				rt.problem = ""
			}
			return true, e
		}
		return true, rt.manager.Disable(ctx)
	}
	if rt.problem != "" {
		return true, errors.New(rt.problem)
	}
	if head.Action == "internet-refresh" {
		_, e := rt.backend.Preflight(ctx, command.Upstream)
		return true, e
	}
	return true, rt.manager.Enable(ctx, command.Upstream)
}
