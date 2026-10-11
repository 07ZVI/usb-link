// Package coreupdatenotice relays bounded upgrade notices to an authenticated
// owner UI. A queue, snapshot or IPC delivery is never a renderer acknowledgement.
package coreupdatenotice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type Notice struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Phase   string `json:"phase"`
}
type Client struct {
	PID, Session uint32
	Creation     uint64
}
type pending struct {
	notice   Notice
	client   Client
	ctx      context.Context
	ack      chan struct{}
	answered bool
}
type Broker struct {
	sync.Mutex
	current          *pending
	verify           func(Client) error
	timeout, visible time.Duration
	claim            time.Duration
}

func New(verify func(Client) error) *Broker {
	return &Broker{timeout: 20 * time.Second, visible: 3 * time.Second, claim: 6 * time.Second, verify: verify}
}
func validVersion(v string) bool {
	if len(v) < 5 || len(v) > 40 {
		return false
	}
	dots := 0
	component := 0
	for _, c := range v {
		if c == '.' {
			if component == 0 {
				return false
			}
			dots++
			component = 0
		} else if c >= '0' && c <= '9' {
			component++
		} else {
			return false
		}
	}
	return dots == 2 && component > 0
}
func validClient(c Client) bool {
	return c.PID != 0 && c.Session != 0 && c.Session != 0xffffffff && c.Creation != 0
}
func (b *Broker) Notify(ctx context.Context, version, phase string) error {
	if ctx == nil || b.verify == nil || !validVersion(version) || phase != "received" && phase != "installing" {
		return errors.New("CORE_UPDATE_NOTICE_INVALID")
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	p := &pending{notice: Notice{hex.EncodeToString(nonce[:]), version, phase}, ctx: ctx, ack: make(chan struct{}, 1)}
	b.Lock()
	if b.current != nil {
		b.Unlock()
		return errors.New("CORE_UPDATE_NOTICE_BUSY")
	}
	b.current = p
	b.Unlock()
	defer func() {
		b.Lock()
		if b.current == p {
			b.current = nil
		}
		b.Unlock()
	}()
	// A background service must be upgradable while no desktop UI is running.
	// If no authenticated UI claims the notice in time, proceed unnoticed; once
	// a UI has claimed it, its acknowledgement is still required.
	var unclaimed <-chan time.Time
	if b.claim > 0 {
		t := time.NewTimer(b.claim)
		defer t.Stop()
		unclaimed = t.C
	}
wait:
	for {
		select {
		case <-p.ack:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			break wait
		case <-unclaimed:
			b.Lock()
			none := p.client == (Client{})
			b.Unlock()
			if none {
				return parent.Err()
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := b.verify(p.client); err != nil {
		return err
	}
	if phase == "installing" {
		// Renderer acknowledgement came first; retain the pre-install visible time.
		// Transport allows UI polling/show startup plus the unchanged local eight-
		// second renderer acknowledgement deadline. Visibility adds three seconds.
		timer := time.NewTimer(b.visible)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-parent.Done():
			return parent.Err()
		}
		if err := b.verify(p.client); err != nil {
			return err
		}
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	return nil
}
func (b *Broker) Snapshot(c Client) *Notice {
	b.Lock()
	defer b.Unlock()
	p := b.current
	if !validClient(c) || p == nil || p.ctx.Err() != nil || p.answered {
		return nil
	}
	if p.client == (Client{}) {
		p.client = c
	}
	if p.client != c {
		return nil
	}
	n := p.notice
	return &n
}
func (b *Broker) Reply(c Client, n Notice) error {
	b.Lock()
	defer b.Unlock()
	p := b.current
	if !validClient(c) || p == nil || p.ctx.Err() != nil || p.answered || p.client != c || n != p.notice {
		return errors.New("CORE_UPDATE_NOTICE_STALE")
	}
	p.answered = true
	p.ack <- struct{}{}
	return nil
}
