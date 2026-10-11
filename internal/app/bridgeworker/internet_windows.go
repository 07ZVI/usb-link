//go:build windows && amd64

package bridgeworker

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/transport/routing"
	"sync"
	"time"
)

// A short-lived protected core lease never replaces USB/parent authorization.
// Packet admission checks its deadline on every packet, including core crashes.
type internetPolicy struct {
	mu          sync.Mutex
	lease       routing.Lease
	observation routing.Observation
	root        string
	dir         string
}

func newInternetPolicy(ctx context.Context, root string) *internetPolicy {
	p := &internetPolicy{root: root}
	if root == "" {
		return p
	}
	dir, e := connectioninstall.DependencyDirectory()
	if e != nil {
		return p
	}
	p.dir = dir
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				p.refresh()
			}
		}
	}()
	return p
}
func (p *internetPolicy) refresh() {
	p.mu.Lock()
	defer p.mu.Unlock()
	path := filepath.Join(p.dir, "internet-session.json")
	var lease routing.Lease
	if connectioninstall.VerifyDependencyPath(path) == nil {
		data, e := os.ReadFile(path)
		if e == nil && len(data) < 64<<10 {
			_ = json.Unmarshal(data, &lease)
		}
	}
	if lease.Epoch != p.lease.Epoch {
		p.observation = routing.Observation{Epoch: lease.Epoch}
	}
	p.lease = lease
	if !lease.Valid(p.root, time.Now()) {
		return
	}
	out, _ := json.Marshal(p.observation)
	path = filepath.Join(p.dir, "internet-observation.json")
	if _, e := os.Lstat(path); e == nil && connectioninstall.VerifyDependencyPath(path) != nil {
		return
	}
	// Core treats partial writes as no observation; publication never grants access.
	_ = os.WriteFile(path, out, 0600)
}
func (p *internetPolicy) allow(a netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lease.Allow(a, p.root, time.Now())
}
func (p *internetPolicy) enabled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lease.Valid(p.root, time.Now())
}
func (p *internetPolicy) packet(inbound bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if inbound {
		p.observation.Inbound = true
	} else {
		p.observation.Outbound = true
	}
}
func (p *internetPolicy) ack() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lease.Valid(p.root, time.Now()) {
		p.observation.DHCPACK = true
	}
}
