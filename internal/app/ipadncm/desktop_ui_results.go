package ipadncm

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

const desktopUIResultLimit = 40 << 10

// Correlated local replies survive snapshot polling and are consumed only by
// their renderer acknowledgement. No credentials belong in this cache.
type desktopUIResultCache struct {
	sync.Mutex
	rows    map[string]desktopUIResult
	reading map[string]*desktopUIRead
}
type desktopUIRead struct {
	id   string
	done chan struct{}
}
type desktopUIResult struct {
	data json.RawMessage
	at   time.Time
}

func desktopResultKey(event, id string) string { return event + ":" + id }
func (c *desktopUIResultCache) put(event, id, action string, message any, now time.Time) {
	b, err := json.Marshal(message)
	if err != nil || len(b) > desktopUIResultLimit {
		problem := "UI_RESULT_TOO_LARGE"
		if event == "smb-account" || event == "share-folders" {
			problem = "SMB_RESULT_TOO_LARGE"
		}
		b, _ = json.Marshal(map[string]any{"event": event, "request_id": id, "action": action, "problem": problem})
	}
	c.Lock()
	defer c.Unlock()
	if c.rows == nil {
		c.rows = map[string]desktopUIResult{}
	}
	for k, r := range c.rows {
		if now.Sub(r.at) > 2*time.Minute {
			delete(c.rows, k)
		}
	}
	if len(c.rows) >= 32 {
		var oldest string
		var at time.Time
		for k, r := range c.rows {
			if oldest == "" || r.at.Before(at) {
				oldest, at = k, r.at
			}
		}
		delete(c.rows, oldest)
	}
	c.rows[desktopResultKey(event, id)] = desktopUIResult{b, now}
}
func (c *desktopUIResultCache) get(event, id string, now time.Time) json.RawMessage {
	c.Lock()
	defer c.Unlock()
	r, ok := c.rows[desktopResultKey(event, id)]
	if !ok || now.Sub(r.at) > 2*time.Minute {
		return nil
	}
	return append(json.RawMessage(nil), r.data...)
}
func (c *desktopUIResultCache) ack(event, id string) {
	c.Lock()
	defer c.Unlock()
	delete(c.rows, desktopResultKey(event, id))
}

// Start at most one expensive read per result kind. The authenticated pipe can
// return a pending reply immediately; completion uses the existing ID/ack path.
func (c *desktopUIResultCache) startRead(ctx context.Context, event, id, action string, read func() any) (<-chan struct{}, bool) {
	c.Lock()
	if active := c.reading[event]; active != nil {
		c.Unlock()
		return active.done, active.id == id
	}
	if ctx.Err() != nil {
		c.Unlock()
		return nil, false
	}
	if c.reading == nil {
		c.reading = make(map[string]*desktopUIRead)
	}
	work := &desktopUIRead{id: id, done: make(chan struct{})}
	c.reading[event] = work
	c.Unlock()
	go func() {
		defer func() { c.Lock(); delete(c.reading, event); close(work.done); c.Unlock() }()
		message := read()
		if ctx.Err() == nil {
			c.put(event, id, action, message, time.Now())
		}
	}()
	return work.done, true
}
