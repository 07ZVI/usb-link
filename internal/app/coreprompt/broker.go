// Package coreprompt relays one cancellable, bounded UI question. Answers
// select existing consent; they never establish a device or process identity.
package coreprompt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

type Check struct {
	Text     string `json:"text"`
	Checked  bool   `json:"checked"`
	Disabled bool   `json:"disabled"`
}
type Question struct {
	Dependency string  `json:"dependency,omitempty"`
	ID         string  `json:"id"`
	Title      string  `json:"title"`
	Body       string  `json:"body"`
	Accept     string  `json:"accept"`
	Checks     []Check `json:"checks"`
}
type Answer struct {
	ID       string `json:"id"`
	Accepted bool   `json:"accepted"`
	Checks   []bool `json:"checks"`
}
type pending struct {
	question Question
	ctx      context.Context
	reply    chan Answer
	answered bool
}
type Broker struct {
	sync.Mutex
	current *pending
	slot    chan struct{}
}

func New() *Broker { return &Broker{slot: make(chan struct{}, 1)} }
func (b *Broker) Ask(ctx context.Context, q Question) (Answer, error) {
	size := len(q.Title) + len(q.Body) + len(q.Accept) + len(q.Dependency)
	if q.Dependency != "" && q.Dependency != "apple-support" {
		return Answer{}, fmt.Errorf("CORE_PROMPT_DEPENDENCY_INVALID")
	}
	for _, check := range q.Checks {
		size += len(check.Text)
	}
	if ctx == nil || ctx.Err() != nil || len(q.Checks) > 16 || size > 16384 {
		return Answer{}, fmt.Errorf("CORE_PROMPT_INVALID")
	}
	select {
	case b.slot <- struct{}{}:
	case <-ctx.Done():
		return Answer{}, ctx.Err()
	}
	defer func() { <-b.slot }()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Answer{}, err
	}
	q.ID = hex.EncodeToString(nonce[:])
	q.Checks = append([]Check(nil), q.Checks...)
	p := &pending{question: q, ctx: ctx, reply: make(chan Answer, 1)}
	b.Lock()
	b.current = p
	b.Unlock()
	defer func() {
		b.Lock()
		if b.current == p {
			b.current = nil
		}
		b.Unlock()
	}()
	select {
	case a := <-p.reply:
		if ctx.Err() != nil {
			return Answer{}, ctx.Err()
		}
		return a, nil
	case <-ctx.Done():
		return Answer{}, ctx.Err()
	}
}
func (b *Broker) Snapshot() *Question {
	b.Lock()
	defer b.Unlock()
	if b.current == nil || b.current.answered || b.current.ctx.Err() != nil {
		return nil
	}
	q := b.current.question
	q.Checks = append([]Check(nil), q.Checks...)
	return &q
}
func (b *Broker) Reply(a Answer) error {
	b.Lock()
	defer b.Unlock()
	p := b.current
	if p == nil || p.answered || p.ctx.Err() != nil || a.ID != p.question.ID || len(a.Checks) != len(p.question.Checks) {
		return fmt.Errorf("CORE_PROMPT_STALE")
	}
	for i, c := range p.question.Checks {
		if c.Disabled && a.Checks[i] != c.Checked {
			return fmt.Errorf("CORE_PROMPT_DISABLED_CHANGED")
		}
	}
	p.answered = true
	a.Checks = append([]bool(nil), a.Checks...)
	p.reply <- a
	return nil
}
