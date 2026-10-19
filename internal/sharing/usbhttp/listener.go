// Package usbhttp multiplexes one USB service address by authorized peer.
// Ownership is per registration: detaching one device never closes another.
package usbhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type owner struct {
	handler http.Handler
	ctx     context.Context
	cancel  context.CancelFunc
	active  sync.WaitGroup
}
type listener struct {
	server *http.Server
	peers  map[string]*owner
	done   chan struct{}
}

var registry = struct {
	sync.Mutex
	listeners map[string]*listener
}{listeners: map[string]*listener{}}

// Register serves handler on address for one authorized peer. The owner has its
// own cancellation boundary, so detaching one device never closes another.
func Register(ctx context.Context, address, peer string, handler http.Handler) (func(), error) {
	if net.ParseIP(peer).To4() == nil || handler == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("invalid USB HTTP owner")
	}
	registry.Lock()
	l := registry.listeners[address]
	if l == nil {
		ln, err := net.Listen("tcp4", address)
		if err != nil {
			registry.Unlock()
			return nil, err
		}
		l = &listener{peers: map[string]*owner{}, done: make(chan struct{})}
		l.server = &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 120 * time.Second, WriteTimeout: 125 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 4096}
		l.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			registry.Lock()
			o := l.peers[host]
			if err != nil || o == nil || o.ctx.Err() != nil {
				registry.Unlock()
				http.Error(w, "Authorized USB peer required", 403)
				return
			}
			o.active.Add(1)
			registry.Unlock()
			defer o.active.Done()
			requestCtx, cancel := context.WithCancel(r.Context())
			callbackDone := make(chan struct{})
			stop := context.AfterFunc(o.ctx, func() {
				defer close(callbackDone)
				cancel()
				c := http.NewResponseController(w)
				c.SetReadDeadline(time.Now())
				c.SetWriteDeadline(time.Now())
				r.Body.Close()
			})
			defer func() {
				if !stop() {
					<-callbackDone
				}
			}()
			defer cancel()
			o.handler.ServeHTTP(w, r.WithContext(requestCtx))
		})
		registry.listeners[address] = l
		go func() { defer close(l.done); l.server.Serve(ln) }()
	}
	if l.peers[peer] != nil {
		registry.Unlock()
		return nil, fmt.Errorf("USB peer already registered")
	}
	ownerCtx, cancel := context.WithCancel(ctx)
	o := &owner{handler: handler, ctx: ownerCtx, cancel: cancel}
	l.peers[peer] = o
	registry.Unlock()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			registry.Lock()
			delete(l.peers, peer)
			o.cancel()
			last := len(l.peers) == 0
			// Keep the address reserved until the final listener has actually closed.
			if last {
				l.server.Close()
				delete(registry.listeners, address)
			}
			registry.Unlock()
			if last {
				<-l.done
			}
			o.active.Wait()
		})
	}
	go func() { <-ownerCtx.Done(); stop() }()
	return stop, nil
}
