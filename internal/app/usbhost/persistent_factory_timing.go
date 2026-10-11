package usbhost

import (
	"sync"
	"time"
)

type PersistentFactoryTiming struct {
	Count    uint64 `json:"count"`
	Failures uint64 `json:"failures"`
	LastMS   int64  `json:"last_ms"`
	TotalMS  int64  `json:"total_ms"`
}

var persistentFactoryTimings struct {
	sync.Mutex
	rows map[string]PersistentFactoryTiming
}

func persistentFactoryPhase(name string) func(error) {
	allowed := false
	switch name {
	case "capture", "recovery", "create", "proof_checkpoint", "close_checkpoint", "restore_originals", "remove_exact":
		allowed = true
	}
	start := time.Now()
	return func(e error) {
		if !allowed {
			return
		}
		persistentFactoryTimings.Lock()
		defer persistentFactoryTimings.Unlock()
		if persistentFactoryTimings.rows == nil {
			persistentFactoryTimings.rows = make(map[string]PersistentFactoryTiming, 7)
		}
		v := persistentFactoryTimings.rows[name]
		v.Count++
		if e != nil {
			v.Failures++
		}
		v.LastMS = time.Since(start).Milliseconds()
		v.TotalMS += v.LastMS
		persistentFactoryTimings.rows[name] = v
	}
}

// Fixed process-local operation names/counts only. No journal, tokens, network
// GUIDs, arbitrary errors, paths or original values enter runtime diagnostics.
func PersistentHostFactoryTimingsSnapshot() map[string]PersistentFactoryTiming {
	persistentFactoryTimings.Lock()
	defer persistentFactoryTimings.Unlock()
	out := make(map[string]PersistentFactoryTiming, len(persistentFactoryTimings.rows))
	for k, v := range persistentFactoryTimings.rows {
		out[k] = v
	}
	return out
}
