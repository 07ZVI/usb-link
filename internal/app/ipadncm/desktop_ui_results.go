package ipadncm

import (
	"encoding/json"
	"sync"
	"time"
)

const desktopUIResultLimit = 40 << 10

// Correlated local replies survive snapshot polling and are consumed only by
// their renderer acknowledgement. No credentials belong in this cache.
type desktopUIResultCache struct {
	sync.Mutex
	rows map[string]desktopUIResult
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
