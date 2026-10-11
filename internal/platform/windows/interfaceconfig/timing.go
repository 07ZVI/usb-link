package interfaceconfig

import (
	"sync"
	"time"
)

// ObservationsSnapshot contains process-local measurements only. It is bounded
// to fixed operations/roles and never returns receipts or interface identity.
type OperationTiming struct {
	Role       string `json:"role"`
	Kind       string `json:"kind"`
	Calls      uint64 `json:"calls"`
	Failures   uint64 `json:"failures"`
	Disabled   uint64 `json:"disabled"`
	DurationMS int64  `json:"duration_ms"`
}

var timings struct {
	sync.Mutex
	values map[string]OperationTiming
}

func recordTiming(role, kind string, start time.Time, e error, disabled bool) {
	if role != "host" && role != "mac" && role != "ipad" {
		return
	}
	switch kind {
	case "dad_apply", "dad_restore", "owned_dad_apply", "persistent_apply", "persistent_restore", "persistent_reuse":
	default:
		return
	}
	timings.Lock()
	defer timings.Unlock()
	if timings.values == nil {
		timings.values = map[string]OperationTiming{}
	}
	key := role + ":" + kind
	v := timings.values[key]
	v.Role, v.Kind = role, kind
	v.Calls++
	v.DurationMS += time.Since(start).Milliseconds()
	if e != nil {
		v.Failures++
	}
	if disabled {
		v.Disabled++
	}
	timings.values[key] = v
}
func ObservationsSnapshot() []OperationTiming {
	timings.Lock()
	defer timings.Unlock()
	out := []OperationTiming{}
	for _, role := range []string{"host", "mac", "ipad"} {
		for _, kind := range []string{"dad_apply", "dad_restore", "owned_dad_apply", "persistent_apply", "persistent_restore", "persistent_reuse"} {
			if v, ok := timings.values[role+":"+kind]; ok {
				out = append(out, v)
			}
		}
	}
	return out
}
